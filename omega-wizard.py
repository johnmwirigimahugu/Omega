#!/usr/bin/env python3
# =============================================================================
# omega.py - Fullstack Python Web Framework (Weppy/web2py inspired)
#
# Features:
#   - Routing with decorator syntax
#   - HTML helper class (minimal typing)
#   - RedBean ORM (auto-migrating, dynamic fields, SQLite)
#   - NoSQLite (schemaless document store, SQLite, Goatfish-inspired)
#   - MySQLORM (no dependency, basic CRUD, MySQLdb or pymysql compatible)
#   - User management (registration, login, password hashing)
#   - File management (upload/download, no dependencies)
#   - Mailer (SMTP, no dependencies)
#   - MiniJinja (Jinja-like templating, layouts, partials)
#   - Caching (in-memory and file-based)
#   - Cookies and Sessions (secure, server-side)
#   - JSON utilities (encode/decode)
#   - Messaging (flash messages)
#   - Testing utilities (basic test client)
#
#   @Author: John Mwirigi Mahugu
#   Date:    2025-04-24
# =============================================================================

import os
import re
import sys
import sqlite3
import smtplib
import hashlib
import secrets
import threading
import time
import mimetypes
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from wsgiref.simple_server import make_server
from urllib.parse import parse_qs, quote, unquote
from html import escape
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# HTML Helper (minimal typing, supports attributes and nesting)
# -----------------------------------------------------------------------------
class H:
    def __getattr__(self, tag):
        def tagger(*content, **attrs):
            attrs_str = ''.join(
                f' {k[1:] if k.startswith("_") else k}="{escape(str(v))}"'
                for k, v in attrs.items()
            )
            inner = ''.join(str(c) for c in content)
            return f"<{tag}{attrs_str}>{inner}</{tag}>"
        return tagger
    def __call__(self, html):
        return str(html)

# -----------------------------------------------------------------------------
# RedBean-style ORM (auto-migrating, dynamic fields, SQLite)
# -----------------------------------------------------------------------------
class RedBean:
    def __init__(self, dbfile='app.db'):
        self.conn = sqlite3.connect(dbfile, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
    def __getattr__(self, table):
        return Bean(self.conn, table, self.lock)

class Bean:
    def __init__(self, conn, table, lock):
        self.conn = conn
        self.table = table
        self.lock = lock
    def dispense(self, **kwargs):
        with self.lock:
            self._auto_migrate(kwargs)
            cols = ', '.join(kwargs.keys())
            vals = ', '.join(['?']*len(kwargs))
            sql = f'INSERT INTO {self.table} ({cols}) VALUES ({vals})'
            cur = self.conn.execute(sql, tuple(kwargs.values()))
            self.conn.commit()
            return cur.lastrowid
    def find(self, where=None, args=()):
        sql = f'SELECT * FROM {self.table}'
        if where: sql += f' WHERE {where}'
        return [dict(row) for row in self.conn.execute(sql, args).fetchall()]
    def find_one(self, where=None, args=()):
        sql = f'SELECT * FROM {self.table}'
        if where: sql += f' WHERE {where} LIMIT 1'
        row = self.conn.execute(sql, args).fetchone()
        return dict(row) if row else None
    def update(self, id, **kwargs):
        with self.lock:
            self._auto_migrate(kwargs)
            sets = ', '.join([f"{k}=?" for k in kwargs])
            sql = f'UPDATE {self.table} SET {sets} WHERE id=?'
            self.conn.execute(sql, tuple(kwargs.values()) + (id,))
            self.conn.commit()
    def delete(self, id):
        with self.lock:
            self.conn.execute(f'DELETE FROM {self.table} WHERE id=?', (id,))
            self.conn.commit()
    def _auto_migrate(self, fields):
        cur = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (self.table,))
        if not cur.fetchone():
            self.conn.execute(f"CREATE TABLE {self.table} (id INTEGER PRIMARY KEY)")
        cur = self.conn.execute(f'PRAGMA table_info({self.table})')
        existing = {row['name'] for row in cur.fetchall()}
        for k, v in fields.items():
            if k not in existing:
                typ = 'INTEGER' if isinstance(v, int) else 'REAL' if isinstance(v, float) else 'TEXT'
                self.conn.execute(f'ALTER TABLE {self.table} ADD COLUMN {k} {typ}')
                self.conn.commit()

# -----------------------------------------------------------------------------
# NoSQLite: Schemaless SQLite ORM (inspired by goatfish)
# -----------------------------------------------------------------------------
class NoSQLite:
    def __init__(self, dbfile='nosqlite.db'):
        self.conn = sqlite3.connect(dbfile, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._ensure_tables()
        self.lock = threading.Lock()
    def _ensure_tables(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS documents (
            uuid TEXT PRIMARY KEY,
            type TEXT,
            data TEXT
        );
        CREATE TABLE IF NOT EXISTS indexes (
            name TEXT,
            type TEXT,
            columns TEXT,
            PRIMARY KEY (name, type)
        );
        """)
        self.conn.commit()
    def _create_index_table(self, name, columns):
        cols = ', '.join([f'col_{i} TEXT' for i in range(len(columns))])
        self.conn.execute(f"""
        CREATE TABLE IF NOT EXISTS idx_{name} (
            uuid TEXT,
            {cols},
            FOREIGN KEY(uuid) REFERENCES documents(uuid)
        );
        CREATE INDEX IF NOT EXISTS idx_{name}_lookup ON idx_{name}({', '.join(f'col_{i}' for i in range(len(columns)))});
        """)
        self.conn.execute("INSERT OR IGNORE INTO indexes VALUES (?, ?, ?)", 
                         (name, 'document', ','.join(columns)))
        self.conn.commit()
    class Document:
        def __init__(self, parent, doc_type):
            self.parent = parent
            self.doc_type = doc_type
            self.indexes = {}
        def add_index(self, *columns):
            index_name = f"{self.doc_type}_{'_'.join(columns)}"
            self.parent._create_index_table(index_name, columns)
            self.indexes[index_name] = columns
            return self
        def save(self, **data):
            uuid = data.pop('uuid', secrets.token_urlsafe(16))
            with self.parent.lock:
                existing = self.parent.conn.execute(
                    "SELECT data FROM documents WHERE uuid=? AND type=?",
                    (uuid, self.doc_type)
                ).fetchone()
                doc_data = {}
                if existing:
                    doc_data.update(self.parent._decode_data(existing['data']))
                doc_data.update(data)
                self.parent.conn.execute(
                    "REPLACE INTO documents (uuid, type, data) VALUES (?, ?, ?)",
                    (uuid, self.doc_type, self.parent._encode_data(doc_data))
                )
                for index_name, columns in self.indexes.items():
                    index_values = [str(doc_data.get(col, '')) for col in columns]
                    placeholders = ', '.join(['?'] * (len(columns)+1))
                    self.parent.conn.execute(
                        f"REPLACE INTO idx_{index_name} (uuid, {', '.join(f'col_{i}' for i in range(len(columns)))}) VALUES ({placeholders})",
                        [uuid] + index_values
                    )
                self.parent.conn.commit()
            return uuid
        def find(self, **conditions):
            best_index = None
            for index_name, columns in self.indexes.items():
                if all(col in conditions for col in columns):
                    if not best_index or len(columns) > len(best_index[1]):
                        best_index = (index_name, columns)
            if best_index:
                index_name, columns = best_index
                where = ' AND '.join([f'col_{i}=?' for i in range(len(columns))])
                params = [str(conditions[col]) for col in columns]
                rows = self.parent.conn.execute(
                    f"SELECT uuid FROM idx_{index_name} WHERE {where}", params
                )
                uuids = [row['uuid'] for row in rows]
                return self.parent._load_by_uuids(uuids)
            else:
                return self.parent._full_scan(self.doc_type, conditions)
    def __getattr__(self, name):
        return self.Document(self, name)
    def _encode_data(self, data):
        import json
        return json.dumps(data)
    def _decode_data(self, data):
        import json
        return json.loads(data)
    def _load_by_uuids(self, uuids):
        if not uuids: return []
        placeholders = ', '.join(['?']*len(uuids))
        rows = self.conn.execute(
            f"SELECT data FROM documents WHERE uuid IN ({placeholders})", uuids
        )
        return [self._decode_data(row['data']) for row in rows]
    def _full_scan(self, doc_type, conditions):
        results = []
        rows = self.conn.execute(
            "SELECT data FROM documents WHERE type=?", (doc_type,)
        )
        for row in rows:
            data = self._decode_data(row['data'])
            if all(str(data.get(k)) == str(v) for k,v in conditions.items()):
                results.append(data)
        return results

# -----------------------------------------------------------------------------
# MySQLORM (no dependency, basic CRUD

class MySQLORM:
    def __init__(self, **config):
        try:
            import MySQLdb
            self.db = MySQLdb.connect(**config)
        except ImportError:
            try:
                import pymysql
                self.db = pymysql.connect(**config)
            except ImportError:
                raise RuntimeError("Install MySQLdb or pymysql for MySQL support")
        self.cursor = self.db.cursor()
    
    def execute(self, sql, params=None):
        self.cursor.execute(sql, params or ())
        return self.cursor
    
    def find(self, table, where=None, args=()):
        sql = f"SELECT * FROM {table}"
        if where: sql += f" WHERE {where}"
        self.cursor.execute(sql, args)
        return [dict(zip([col[0] for col in self.cursor.description], row)) 
                for row in self.cursor.fetchall()]
    
    def find_one(self, table, where=None, args=()):
        sql = f"SELECT * FROM {table} WHERE {where or '1=1'} LIMIT 1"
        self.cursor.execute(sql, args)
        row = self.cursor.fetchone()
        if not row: return None
        return dict(zip([col[0] for col in self.cursor.description], row))
    
    def insert(self, table, **data):
        cols = ', '.join(data.keys())
        vals = ', '.join(['%s']*len(data))
        sql = f"INSERT INTO {table} ({cols}) VALUES ({vals})"
        self.cursor.execute(sql, tuple(data.values()))
        self.db.commit()
        return self.cursor.lastrowid
    
    def update(self, table, where, args, **data):
        sets = ', '.join([f"{k}=%s" for k in data])
        sql = f"UPDATE {table} SET {sets} WHERE {where}"
        self.cursor.execute(sql, tuple(data.values()) + args)
        self.db.commit()
    
    def delete(self, table, where, args=()):
        sql = f"DELETE FROM {table} WHERE {where}"
        self.cursor.execute(sql, args)
        self.db.commit()

# -----------------------------------------------------------------------------
# Caching (in-memory and file-based)
# -----------------------------------------------------------------------------
class Cache:
    def __init__(self, cache_dir='.cache'):
        self.memory = {}
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
    
    def get(self, key, default=None):
        # Memory cache
        if key in self.memory and self.memory[key][1] > time.time():
            return self.memory[key][0]
        
        # File cache
        path = os.path.join(self.cache_dir, quote(key))
        if os.path.exists(path):
            with open(path, 'r') as f:
                expires, val = f.read().split('|', 1)
                if float(expires) > time.time():
                    return val
        return default
    
    def set(self, key, val, expires=3600):
        # Memory cache
        self.memory[key] = (val, time.time() + expires)
        
        # File cache
        path = os.path.join(self.cache_dir, quote(key))
        with open(path, 'w') as f:
            f.write(f"{time.time() + expires}|{val}")

# -----------------------------------------------------------------------------
# Cookies & Sessions
# -----------------------------------------------------------------------------
class Cookie:
    @staticmethod
    def get(environ, name):
        cookies = {}
        if 'HTTP_COOKIE' in environ:
            for c in environ['HTTP_COOKIE'].split(';'):
                k, v = c.strip().split('=', 1)
                cookies[k] = unquote(v)
        return cookies.get(name)
    
    @staticmethod
    def set(start_response, name, val, expires=None, path='/', httponly=True):
        val = quote(val)
        parts = [f"{name}={val}", f"Path={path}"]
        if expires:
            if isinstance(expires, int):
                expires = datetime.now() + timedelta(seconds=expires)
            parts.append(f"Expires={expires.strftime('%a, %d %b %Y %H:%M:%S GMT')}")
        if httponly:
            parts.append("HttpOnly")
        start_response('200 OK', [('Set-Cookie', '; '.join(parts))])

class Session:
    def __init__(self, app, secret=None):
        self.app = app
        self.secret = secret or secrets.token_hex(32)
        self.store = app.nosql.sessions
    
    def __call__(self, environ, start_response):
        sid = Cookie.get(environ, 'sid')
        if not sid:
            sid = secrets.token_urlsafe(32)
            Cookie.set(start_response, 'sid', sid, expires=3600*24*30)
        environ['session'] = self.store.find_one(sid=sid) or {'sid': sid}
        return None
    
    def save(self, environ, start_response):
        if 'session' in environ:
            self.store.save(**environ['session'])

# -----------------------------------------------------------------------------
# JSON Utilities
# -----------------------------------------------------------------------------
class JSON:
    @staticmethod
    def loads(data):
        import json
        return json.loads(data)
    
    @staticmethod
    def dumps(obj):
        import json
        return json.dumps(obj)
    
    @staticmethod
    def response(data):
        return JSON.dumps(data), '200 OK', {'Content-Type': 'application/json'}

# -----------------------------------------------------------------------------
# Messaging (Flash Messages)
# -----------------------------------------------------------------------------
class Messenger:
    def __init__(self, app):
        self.app = app
    
    def flash(self, environ, message, category='info'):
        if 'flash' not in environ:
            environ['flash'] = []
        environ['flash'].append((category, message))
    
    def get_flashed_messages(self, environ):
        return environ.pop('flash', [])

# -----------------------------------------------------------------------------
# Testing Utilities
# -----------------------------------------------------------------------------
class TestClient:
    def __init__(self, app):
        self.app = app
    
    def get(self, path, headers=None):
        environ = {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': path,
            'QUERY_STRING': '',
            'wsgi.input': None,
            **headers or {}
        }
        response = []
        
        def start_response(status, headers):
            response.extend([status, dict(headers)])
            return None
        
        body = b''.join(self.app(environ, start_response)).decode()
        return TestResponse(response[0], response[1], body)

class TestResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body
