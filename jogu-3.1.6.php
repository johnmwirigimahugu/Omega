<?php
/*  @Author : John Mwirigi Mahugu - "Kesh"
 *  @dedication : To Our God and All My Loved ones ESPECIALLY Seth my son. May this inspire you and serve you well in your computer science career.
 *  @email address : johnmahugu[at]gmail[dot]com
 *  @Mobile Number : +254722925095
 *  @linked-in : https://linkedin.com/in/johnmahugu
 *  @website : https://sites.google.com/view/mahugu
 *  @website : https://about.me/mahugu
 *  @website : https://pastebin.com/u/johnmahugu
 *  @repository : https://gitlab.com/johnmahugu
 * Jogu PHP Micro-Framework
 * Version: 3.0
 * Start Date: 2025-04-17 03:16 EAT [my eldest sibling Patos Birthday :)]
 * Last Update: 2025-04-24 03:16 EAT [Life Analytics Sign JPN] deployed to GIT/johnmwirigimahugu and Gitlab/johnmwirigimahugu 
 *
* ============================================================================
* 
* Copyright (C) 2025 by John "Kesh" Mahugu
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
* 
 *
 * Features:
 * 1 - Flexible routing with :param and {param} + regex constraints
 * 2 - Route grouping and namespaces
 * 3 - Jinja-like templating engine with {% extends %} and {% block %}
 * 4 - Secure user management via PHP sessions
 * 5 - JSON input/output helpers
 * 6 - File upload handler
 * 7 - Simple email sender
 * 8 - PDO-based ORM inspired by RedBeanPHP
 * 9 - Plugin system for middleware/extensions
 * 10 - Static file handler for development
 * 11 - Error handling/exception middleware
 * 12 - Request/response objects
 * 13 - Logging utility
 * 14 - CORS and security headers
 * 15 - Testing utilities
 * 16 - CLI runner for tasks/scripts
 * 17 - Configuration loader (YAML/INI/ENV)
 * 18 - Rate limiting/throttling
 * 19 - CSRF protection
 * 20 - Flash messages
 * 21 - Internationalization (i18n) support
 * 22 - cURL helper class
 * 23 - File downloader class
 * 24 - Paginator class
 * 25 - NoSQL ORM class
 * 26 - Dependency Injection Class
 * 27 - Testing Class
 */


// ----------- Request & Response -----------
class Request {
    public $method, $uri, $path, $query = [], $headers = [], $body, $cookies = [], $files = [], $ip, $ua, $params = [];
    public function __construct() {
        $this->method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->uri = $_SERVER['REQUEST_URI'] ?? '/';
        $this->path = parse_url($this->uri, PHP_URL_PATH);
        $this->query = $_GET;
        $this->cookies = $_COOKIE;
        $this->files = $_FILES;
        $this->ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $this->ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') === 0) {
                $header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($k, 5)))));
                $this->headers[$header] = $v;
            }
        }
        $ct = $_SERVER['CONTENT_TYPE'] ?? '';
        if (strpos($ct, 'application/json') !== false) {
            $this->body = json_decode(file_get_contents('php://input'), true);
        } elseif (strpos($ct, 'application/x-www-form-urlencoded') !== false) {
            $this->body = $_POST;
        } else {
            $this->body = file_get_contents('php://input');
        }
    }
}

class Response {
    public $status = 200, $headers = [], $body = '', $cookies = [];
    public function __construct($body = '', $status = 200, $headers = []) {
        $this->body = $body;
        $this->status = $status;
        $this->headers = array_merge(['Content-Type' => 'text/html; charset=UTF-8'], $headers);
    }
    public function withStatus($status) { $this->status = $status; return $this; }
    public function withHeader($name, $value) { $this->headers[$name] = $value; return $this; }
    public function withBody($body) { $this->body = $body; return $this; }
    public function withJson($data, $status = null) {
        $this->headers['Content-Type'] = 'application/json';
        $this->body = json_encode($data);
        if ($status !== null) $this->status = $status;
        return $this;
    }
    public function withCookie($name, $value, $expires = 0, $path = '/', $domain = '', $secure = false, $httpOnly = true) {
        $this->cookies[$name] = compact('value', 'expires', 'path', 'domain', 'secure', 'httpOnly');
        return $this;
    }
    public function redirect($url, $status = 302) {
        $this->status = $status;
        $this->headers['Location'] = $url;
        return $this;
    }
    public function send() {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) header("$k: $v");
        foreach ($this->cookies as $n => $c) {
            setcookie($n, $c['value'], $c['expires'], $c['path'], $c['domain'], $c['secure'], $c['httpOnly']);
        }
        echo $this->body;
        return $this;
    }
}

// ----------- Logger -----------
class Logger {
    const DEBUG=100,INFO=200,NOTICE=250,WARNING=300,ERROR=400,CRITICAL=500,ALERT=550,EMERGENCY=600;
    private $file, $minLevel, $levels;
    public function __construct($file=null, $minLevel=self::DEBUG) {
        $this->file = $file ?? sys_get_temp_dir().'/jogu.log';
        $this->minLevel = $minLevel;
        $this->levels = [
            self::DEBUG=>'DEBUG',self::INFO=>'INFO',self::NOTICE=>'NOTICE',self::WARNING=>'WARNING',
            self::ERROR=>'ERROR',self::CRITICAL=>'CRITICAL',self::ALERT=>'ALERT',self::EMERGENCY=>'EMERGENCY'
        ];
    }
    public function log($level, $message, $context=[]) {
        if ($level < $this->minLevel) return;
        $levelName = $this->levels[$level] ?? 'UNKNOWN';
        $timestamp = date('Y-m-d H:i:s');
        foreach ($context as $k => $v) if (is_scalar($v)) $message = str_replace("{{$k}}", $v, $message);
        $entry = "[$timestamp] [$levelName] $message\n";
        error_log($entry, 3, $this->file);
    }
    public function debug($msg,$ctx=[]) { $this->log(self::DEBUG,$msg,$ctx); }
    public function info($msg,$ctx=[]) { $this->log(self::INFO,$msg,$ctx); }
    public function notice($msg,$ctx=[]) { $this->log(self::NOTICE,$msg,$ctx); }
    public function warning($msg,$ctx=[]) { $this->log(self::WARNING,$msg,$ctx); }
    public function error($msg,$ctx=[]) { $this->log(self::ERROR,$msg,$ctx); }
    public function critical($msg,$ctx=[]) { $this->log(self::CRITICAL,$msg,$ctx); }
    public function alert($msg,$ctx=[]) { $this->log(self::ALERT,$msg,$ctx); }
    public function emergency($msg,$ctx=[]) { $this->log(self::EMERGENCY,$msg,$ctx); }
}

// ----------- Config -----------
class Config {
    private $data = [];
    private static $instance = null;
    private function __construct() {}
    public static function getInstance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }
    public function load($file) {
        $ext = pathinfo($file, PATHINFO_EXTENSION);
        if (!file_exists($file)) throw new Exception("Config file not found: $file");
        switch ($ext) {
            case 'php': $config = include $file; break;
            case 'json': $config = json_decode(file_get_contents($file), true); break;
            case 'ini': $config = parse_ini_file($file, true); break;
            case 'yml': case 'yaml':
                if (!function_exists('yaml_parse_file')) throw new Exception("YAML extension not installed");
                $config = yaml_parse_file($file);
                break;
            default: throw new Exception("Unsupported config format: $ext");
        }
        if (is_array($config)) $this->data = array_merge($this->data, $config);
        return $this;
    }
    public function loadEnv($file = '.env') {
        if (!file_exists($file)) return $this;
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            if (!strpos($line, '=')) continue;
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name); $value = trim($value);
            if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
                putenv("$name=$value");
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
            $this->data['env'][$name] = $value;
        }
        return $this;
    }
    public function get($key, $default = null) {
        $segments = explode('.', $key);
        $data = $this->data;
        foreach ($segments as $seg) {
            if (!isset($data[$seg])) return $default;
            $data = $data[$seg];
        }
        return $data;
    }
    public function set($key, $value) {
        $segments = explode('.', $key);
        $data = &$this->data;
        foreach ($segments as $i => $seg) {
            if ($i === count($segments) - 1) $data[$seg] = $value;
            else {
                if (!isset($data[$seg]) || !is_array($data[$seg])) $data[$seg] = [];
                $data = &$data[$seg];
            }
        }
        return $this;
    }
    public function all() { return $this->data; }
}

// ----------- CSRF -----------
class Csrf {
    private $tokenName = 'jogu_csrf_token';
    private $tokenLength = 32;
    public function __construct() {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }
    public function generateToken() {
        if (!isset($_SESSION[$this->tokenName])) $_SESSION[$this->tokenName] = bin2hex(random_bytes($this->tokenLength / 2));
        return $_SESSION[$this->tokenName];
    }
    public function validateToken($token) {
        return isset($_SESSION[$this->tokenName]) && !empty($token) && hash_equals($_SESSION[$this->tokenName], $token);
    }
    public function getTokenField() {
        return '<input type="hidden" name="'.$this->tokenName.'" value="'.$this->generateToken().'">';
    }
}

// ----------- Flash Messages -----------
class Flash {
    private $key = 'jogu_flash_messages';
    public function __construct() {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        if (!isset($_SESSION[$this->key])) $_SESSION[$this->key] = [];
    }
    public function set($type, $msg) { $_SESSION[$this->key][$type][] = $msg; }
    public function success($msg) { $this->set('success', $msg); }
    public function error($msg) { $this->set('error', $msg); }
    public function warning($msg) { $this->set('warning', $msg); }
    public function info($msg) { $this->set('info', $msg); }
    public function get($type = null) {
        if ($type === null) { $m = $_SESSION[$this->key]; $_SESSION[$this->key] = []; return $m; }
        $m = $_SESSION[$this->key][$type] ?? []; $_SESSION[$this->key][$type] = []; return $m;
    }
    public function has($type = null) {
        if ($type === null) return !empty($_SESSION[$this->key]);
        return !empty($_SESSION[$this->key][$type]);
    }
    public function clear($type = null) {
        if ($type === null) $_SESSION[$this->key] = [];
        else $_SESSION[$this->key][$type] = [];
    }
}

// ----------- Internationalization -----------
class I18n {
    private $locale = 'en';
    private $fallbackLocale = 'en';
    private $translations = [];
    private static $instance = null;
    private function __construct() {}
    public static function getInstance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }
    public function setLocale($locale) { $this->locale = $locale; return $this; }
    public function getLocale() { return $this->locale; }
    public function setFallbackLocale($locale) { $this->fallbackLocale = $locale; return $this; }
    public function loadTranslations($locale, $translations) {
        if (!isset($this->translations[$locale])) $this->translations[$locale] = [];
        $this->translations[$locale] = array_merge($this->translations[$locale], $translations);
        return $this;
    }
    public function loadFromFile($locale, $file) {
        $ext = pathinfo($file, PATHINFO_EXTENSION);
        if (!file_exists($file)) throw new Exception("Translation file not found: $file");
        switch ($ext) {
            case 'php': $translations = include $file; break;
            case 'json': $translations = json_decode(file_get_contents($file), true); break;
            default: throw new Exception("Unsupported translation file format: $ext");
        }
        if (is_array($translations)) $this->loadTranslations($locale, $translations);
        return $this;
    }
    public function translate($key, $params = [], $locale = null) {
        $locale = $locale ?? $this->locale;
        if (isset($this->translations[$locale][$key])) return $this->replaceParams($this->translations[$locale][$key], $params);
        if ($locale !== $this->fallbackLocale && isset($this->translations[$this->fallbackLocale][$key])) return $this->replaceParams($this->translations[$this->fallbackLocale][$key], $params);
        return $key;
    }
    private function replaceParams($text, $params) {
        foreach ($params as $k => $v) $text = str_replace(':'.$k, $v, $text);
        return $text;
    }
}

// ----------- Rate Limiter -----------
class RateLimiter {
    private $storage = [];
    private $window;
    public function __construct($window = 60) { $this->window = $window; }
    public function attempt($key, $max) {
        $now = time();
        $this->cleanup($key, $now);
        $attempts = $this->storage[$key] ?? [];
        if (count($attempts) >= $max) return false;
        $this->storage[$key][] = $now;
        return true;
    }
    public function remaining($key, $max) {
        $this->cleanup($key, time());
        return max(0, $max - count($this->storage[$key] ?? []));
    }
    public function resetAttempts($key) { unset($this->storage[$key]); }
    private function cleanup($key, $now) {
        if (!isset($this->storage[$key])) return;
        $cutoff = $now - $this->window;
        $this->storage[$key] = array_filter($this->storage[$key], fn($t) => $t >= $cutoff);
    }
}

// ----------- Template Engine with Inheritance -----------
class JoguTemplate {
    private $templateFile, $templatesDir, $blocks = [], $parentTemplate = null;
    public function __construct($templateFile, $templatesDir = 'views') {
        $this->templateFile = $templateFile;
        $this->templatesDir = $templatesDir;
    }
    public function render($data = []) {
        $tpl = file_get_contents($this->templatePath($this->templateFile));
        if (preg_match('/\{% extends\s+[\'"](.+?)[\'"]\s+%\}/', $tpl, $m)) {
            $this->parentTemplate = $m[1];
            $tpl = preg_replace('/\{% extends\s+[\'"](.+?)[\'"]\s+%\}/', '', $tpl, 1);
        }
        $this->blocks = $this->extractBlocks($tpl);
        if ($this->parentTemplate) {
            $parentTpl = file_get_contents($this->templatePath($this->parentTemplate));
            $parentBlocks = $this->extractBlocks($parentTpl);
            foreach ($parentBlocks as $name => $content) {
                if (isset($this->blocks[$name])) {
                    $parentTpl = preg_replace('/\{% block ' . preg_quote($name, '/') . ' %\}.*?\{% endblock %\}/s', $this->blocks[$name], $parentTpl);
                }
            }
            $tpl = preg_replace('/\{% block (\w+) %\}(.*?)\{% endblock %\}/s', '$2', $parentTpl);
        } else {
            $tpl = preg_replace('/\{% block (\w+) %\}(.*?)\{% endblock %\}/s', '$2', $tpl);
        }
        $tpl = str_replace('<?', '<?php echo \'<?\'; ?>', $tpl);
        $tpl = preg_replace('/\{\{\s*(.+?)\s*\}\}/', '<?php echo htmlspecialchars($1); ?>', $tpl);
        $tpl = preg_replace('/\{% if (.+?) %\}/', '<?php if ($1): ?>', $tpl);
        $tpl = preg_replace('/\{% elseif (.+?) %\}/', '<?php elseif ($1): ?>', $tpl);
        $tpl = preg_replace('/\{% else %\}/', '<?php else: ?>', $tpl);
        $tpl = preg_replace('/\{% endif %\}/', '<?php endif; ?>', $tpl);
        $tpl = preg_replace('/\{% for (\w+) in (\w+) %\}/', '<?php foreach ($$2 as $$1): ?>', $tpl);
        $tpl = preg_replace('/\{% endfor %\}/', '<?php endforeach; ?>', $tpl);
        $tmp = tempnam(sys_get_temp_dir(), 'jogu_tpl_');
        file_put_contents($tmp, $tpl);
        extract($data);
        ob_start();
        include $tmp;
        $output = ob_get_clean();
        unlink($tmp);
        return $output;
    }
    private function extractBlocks($tpl) {
        $blocks = [];
        if (preg_match_all('/\{% block (\w+) %\}(.*?)\{% endblock %\}/s', $tpl, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) $blocks[$m[1]] = $m[2];
        }
        return $blocks;
    }
    private function templatePath($file) {
        if (strpos($file, '/') === 0 || strpos($file, ':') !== false) return $file;
        return rtrim($this->templatesDir, '/') . '/' . $file;
    }
}

// ----------- File Upload Handler -----------
class Upload {
    public function handle($file, $destination, $allowedTypes = [], $maxSize = 2097152) {
        if (!isset($_FILES[$file])) return ['error' => 'No file uploaded'];
        $f = $_FILES[$file];
        if ($f['error'] !== UPLOAD_ERR_OK) return ['error' => 'Upload error: ' . $f['error']];
        if ($f['size'] > $maxSize) return ['error' => 'File too large'];
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        if (!empty($allowedTypes) && !in_array($ext, $allowedTypes)) return ['error' => 'Invalid file type'];
        $destFile = rtrim($destination, '/') . '/' . uniqid() . '.' . $ext;
        if (!move_uploaded_file($f['tmp_name'], $destFile)) return ['error' => 'Failed to move uploaded file'];
        return ['path' => $destFile, 'name' => $f['name'], 'size' => $f['size'], 'type' => $f['type']];
    }
}

// ----------- Email Sender -----------
class Mailer {
    private $from, $replyTo;
    public function __construct($from = null, $replyTo = null) {
        $this->from = $from;
        $this->replyTo = $replyTo;
    }
    public function send($to, $subject, $body, $isHTML = true, $attachments = []) {
        $headers = [];
        $headers[] = "MIME-Version: 1.0";
        $headers[] = "Content-type: " . ($isHTML ? "text/html" : "text/plain") . "; charset=utf-8";
        if ($this->from) $headers[] = "From: " . $this->from;
        if ($this->replyTo) $headers[] = "Reply-To: " . $this->replyTo;
        foreach ($attachments as $file => $name) {
            if (!file_exists($file)) continue;
        }
        $result = mail($to, $subject, $body, implode("\r\n", $headers));
        return $result;
    }
}

// ----------- Database (PDO Wrapper) -----------
class DB {
    private static $pdo;
    public static function connect($dsn, $user = null, $pass = null, $options = []) {
        self::$pdo = new PDO($dsn, $user, $pass, $options);
        self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    public static function run($sql, $args = []) {
        $stmt = self::$pdo->prepare($sql);
        $stmt->execute($args);
        return $stmt;
    }
    public static function fetch($sql, $args = []) { return self::run($sql, $args)->fetch(PDO::FETCH_ASSOC); }
    public static function fetchAll($sql, $args = []) { return self::run($sql, $args)->fetchAll(PDO::FETCH_ASSOC); }
    public static function lastInsertId() { return self::$pdo->lastInsertId(); }
}

// ----------- Plugin System -----------
class Plugin {
    public function beforeRoute($req, $res) {}
    public function afterRoute($req, $res) {}
}

// ----------- Test Utilities -----------
class Test {
    public static function assertEqual($expected, $actual, $message = '') {
        if ($expected !== $actual) throw new Exception("Assertion failed: $message (Expected: $expected, Actual: $actual)");
    }
}

// ----------- CLI Runner -----------
class CLI {
    public static function run($task, $args = []) {
        if (!is_callable($task)) throw new Exception("Task is not callable");
        call_user_func_array($task, $args);
    }
}

// ----------- Main Application Class -----------
class Jogu {
    private $routes = [], $plugins = [], $errorHandlers = [];
    private $groupPrefix = '';
    private $request, $response, $logger, $config, $csrf, $flash, $i18n, $rateLimiter, $upload, $mailer, $template, $staticDir;

    public function __construct() {
        $this->request = new Request();
        $this->response = new Response();
        $this->logger = new Logger();
        $this->config = Config::getInstance();
        $this->csrf = new Csrf();
        $this->flash = new Flash();
        $this->i18n = I18n::getInstance();
        $this->rateLimiter = new RateLimiter();
        $this->upload = new Upload();
        $this->mailer = new Mailer();
        $this->template = new JoguTemplate('default.html', 'views'); // Default template
    }

    // Routing methods
    public function register($method, $pattern, $callback, $constraints = []) {
        $pattern = $this->groupPrefix . $pattern;
        $regex = $this->patternToRegex($pattern, $constraints);
        $method = strtoupper($method);
        $this->routes[$method][$regex] = $callback;
        return $this;
    }

    private function patternToRegex($pattern, $constraints) {
        $regex = preg_replace_callback(
            '#(:|{)(\w+)(?::([^}]+))?}?#',
            function ($matches) use ($constraints) {
                $name = $matches[2];
                $constraint = $matches[3] ?? ($constraints[$name] ?? '[^/]+');
                return '(?P<' . $name . '>' . $constraint . ')';
            },
            $pattern
        );
        return '^' . str_replace('/', '\/', $regex) . '$';
    }

    public function group($prefix, $callback) {
        $previousPrefix = $this->groupPrefix;
        $this->groupPrefix .= $prefix;
        $callback($this);
        $this->groupPrefix = $previousPrefix;
        return $this;
    }

    // Set static directory
    public function setStaticDir($dir) {
        $this->staticDir = $dir;
        return $this;
    }

    // Error handling
    public function error($code, $handler) {
        $this->errorHandlers[$code] = $handler;
        return $this;
    }

    // Plugin system
    public function addPlugin($plugin) {
        $this->plugins[] = $plugin;
        return $this;
    }

    // Run application
    public function run($path = null) {
        try {
            $path = $path ?? $this->request->path;

            // Static file serving
            if ($this->staticDir && $this->serveStaticFile($path)) {
                return;
            }

            $method = $this->request->method;
            if ($method === 'OPTIONS') {
                $this->handleCors();
                return;
            }

            // CORS and security headers
            $this->addCorsHeaders();
            $this->addSecurityHeaders();

            // Route dispatch
            if (empty($this->routes[$method])) {
                $this->triggerError(405);
                return;
            }

            foreach ($this->routes[$method] as $regex => $callback) {
                if (preg_match("#$regex#i", $path, $matches)) {
                    $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
                    $this->request->params = $params;

                    // Before route plugins
                    foreach ($this->plugins as $plugin) {
                        if (method_exists($plugin, 'beforeRoute')) {
                            $res = $plugin->beforeRoute($this->request, $this->response);
                            if ($res instanceof Response) {
                                $this->response = $res;
                                $this->response->send();
                                return;
                            }
                        }
                    }

                    // Execute route callback
                    $result = $callback($this, $params);

                    // Handle different return types
                    if ($result instanceof Response) {
                        $this->response = $result;
                    } elseif (is_string($result)) {
                        $this->response->withBody($result);
                    } elseif (is_array($result) || is_object($result)) {
                        $this->response->withJson($result);
                    }

                    // After route plugins
                    foreach ($this->plugins as $plugin) {
                        if (method_exists($plugin, 'afterRoute')) {
                            $res = $plugin->afterRoute($this->request, $this->response);
                            if ($res instanceof Response) {
                                $this->response = $res;
                            }
                        }
                    }

                    // Send response
                    $this->response->send();
                    return;
                }
            }

            // Route not found
            $this->triggerError(404);

        } catch (\Exception $e) {
            $this->triggerError(500, $e);
        }
    }

    // Serve static files
    private function serveStaticFile($path) {
        if (empty($this->staticDir)) {
            return false;
        }

        $filePath = $this->staticDir . '/' . ltrim($path, '/');
        if (!file_exists($filePath) || is_dir($filePath)) {
            return false;
        }

        $mimeTypes = [
            'css' => 'text/css',
            'js' => 'application/javascript',
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
            'html' => 'text/html',
            'txt' => 'text/plain',
            'pdf' => 'application/pdf',
            'ico' => 'image/x-icon',
        ];

        $ext = pathinfo($filePath, PATHINFO_EXTENSION);
        $contentType = $mimeTypes[$ext] ?? 'application/octet-stream';

        header('Content-Type: ' . $contentType);
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        return true;
    }

    // Handle errors
    private function triggerError($code, \Exception $exception = null) {
        $handler = $this->errorHandlers[$code] ?? $this->errorHandlers[500] ?? null;
        if ($handler) {
            $response = $handler($exception);
            if ($response instanceof Response) {
                $response->send();
            }
        } else {
            http_response_code($code);
            echo "<h1>$code Error</h1>";
            if ($exception && $this->config->get('app.debug', false)) {
                echo "<p>" . $exception->getMessage() . "</p><pre>" . $exception->getTraceAsString() . "</pre>";
            }
        }
    }

    // CORS headers
    private function handleCors() {
        $this->addCorsHeaders();
        header('Content-Length: 0');
        http_response_code(204);
        exit;
    }

    private function addCorsHeaders() {
        $origin = $this->config->get('cors.origin', '*');
        $methods = $this->config->get('cors.methods', 'GET, POST, PUT, DELETE, OPTIONS');
        $headers = $this->config->get('cors.headers', 'Content-Type, Authorization');
        $maxAge = $this->config->get('cors.max_age', 86400);

        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Methods: ' . $methods);
        header('Access-Control-Allow-Headers: ' . $headers);
        header('Access-Control-Max-Age: ' . $maxAge);

        if ($origin !== '*') {
            header('Access-Control-Allow-Credentials: true');
        }
    }

    // Security headers
    private function addSecurityHeaders() {
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: no-referrer-when-downgrade');
        header('Content-Security-Policy: default-src \'self\'');
    }

    // Getters for commonly used objects
    public function request() { return $this->request; }
    public function response() { return $this->response; }
    public function logger() { return $this->logger; }
    public function config() { return $this->config; }
    public function csrf() { return $this->csrf; }
    public function flash() { return $this->flash; }
    public function i18n() { return $this->i18n; }
    public function rateLimiter() { return $this->rateLimiter; }
    public function upload() { return $this->upload; }
    public function mailer() { return $this->mailer; }
    public function template() { return $this->template; }
}
// ----------- cURL Helper -----------
class JoguCurl {
    private $ch, $options = [];
    public function __construct($url = null) {
        $this->ch = curl_init();
        if ($url) $this->setOption(CURLOPT_URL, $url);
        $this->setDefaultOptions();
    }
    private function setDefaultOptions() {
        $this->options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_ENCODING => ''
        ];
    }
    public function setOption($option, $value) {
        $this->options[$option] = $value;
        return $this;
    }
    public function get($url = null) {
        if ($url) $this->setOption(CURLOPT_URL, $url);
        $this->setOption(CURLOPT_CUSTOMREQUEST, 'GET');
        return $this->execute();
    }
    public function post($data, $url = null) {
        if ($url) $this->setOption(CURLOPT_URL, $url);
        $this->setOption(CURLOPT_POST, true);
        $this->setOption(CURLOPT_POSTFIELDS, $data);
        return $this->execute();
    }
    private function execute() {
        curl_setopt_array($this->ch, $this->options);
        $response = curl_exec($this->ch);
        if (curl_errno($this->ch)) {
            throw new Exception('cURL error: '.curl_error($this->ch));
        }
        return $response;
    }
    public function getInfo($opt = null) {
        return $opt ? curl_getinfo($this->ch, $opt) : curl_getinfo($this->ch);
    }
    public function __destruct() {
        curl_close($this->ch);
    }
}

// ----------- File Downloader -----------
class JoguDownloader {
    private $queue = [];
    private $concurrency = 5;
    private $progressCallback;
    
    public function addDownload($url, $destPath) {
        $this->queue[] = ['url' => $url, 'dest' => $destPath];
        return $this;
    }
    
    public function setConcurrency($num) {
        $this->concurrency = max(1, (int)$num);
        return $this;
    }
    
    public function setProgressCallback(callable $callback) {
        $this->progressCallback = $callback;
        return $this;
    }
    
    public function run() {
        $mh = curl_multi_init();
        $handles = [];
        
        // Initialize first batch
        for ($i=0; $i<min($this->concurrency, count($this->queue)); $i++) {
            $handles[$i] = $this->initHandle($this->queue[$i]);
            curl_multi_add_handle($mh, $handles[$i]);
        }
        
        do {
            $status = curl_multi_exec($mh, $active);
            if ($active) {
                curl_multi_select($mh);
            }
            while ($info = curl_multi_info_read($mh)) {
                $this->processCompleted($info['handle']);
                curl_multi_remove_handle($mh, $info['handle']);
                
                // Add next download from queue
                if (count($this->queue) > 0) {
                    $next = array_shift($this->queue);
                    $handle = $this->initHandle($next);
                    curl_multi_add_handle($mh, $handle);
                    $handles[] = $handle;
                }
            }
        } while ($active && $status == CURLM_OK);
        
        curl_multi_close($mh);
    }
    
    private function initHandle($job) {
        $fp = fopen($job['dest'], 'w+');
        $ch = curl_init($job['url']);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => function($ch, $dltotal, $dlnow) use ($job) {
                if ($this->progressCallback && $dltotal > 0) {
                    call_user_func($this->progressCallback, $job['url'], $dlnow, $dltotal);
                }
            }
        ]);
        return $ch;
    }
    
    private function processCompleted($ch) {
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($status !== 200) {
            throw new Exception("Download failed: HTTP $status");
        }
        fclose(curl_getinfo($ch, CURLOPT_FILE));
    }
}

// ----------- Pagination -----------
class Paginator {
    private $totalItems, $itemsPerPage, $currentPage, $urlPattern;
    public function __construct($totalItems, $itemsPerPage, $currentPage, $urlPattern) {
        $this->totalItems = $totalItems;
        $this->itemsPerPage = $itemsPerPage;
        $this->currentPage = $currentPage;
        $this->urlPattern = $urlPattern;
    }
    public function getTotalPages() {
        return ceil($this->totalItems / $this->itemsPerPage);
    }
    public function getPageLinks($maxLinks = 7) {
        $totalPages = $this->getTotalPages();
        if ($totalPages <= 1) return '';
        $start = max(1, $this->currentPage - floor($maxLinks / 2));
        $end = min($totalPages, $start + $maxLinks - 1);
        if ($end - $start < $maxLinks - 1) $start = max(1, $end - $maxLinks + 1);
        $html = '<nav><ul class="pagination">';
        if ($this->currentPage > 1) {
            $prevUrl = str_replace('{page}', $this->currentPage - 1, $this->urlPattern);
            $html .= '<li class="page-item"><a class="page-link" href="'.$prevUrl.'">Previous</a></li>';
        }
        for ($i = $start; $i <= $end; $i++) {
            $url = str_replace('{page}', $i, $this->urlPattern);
            $activeClass = ($i == $this->currentPage) ? ' active' : '';
            $html .= '<li class="page-item'.$activeClass.'"><a class="page-link" href="'.$url.'">'.$i.'</a></li>';
        }
        if ($this->currentPage < $totalPages) {
            $nextUrl = str_replace('{page}', $this->currentPage + 1, $this->urlPattern);
            $html .= '<li class="page-item"><a class="page-link" href="'.$nextUrl.'">Next</a></li>';
        }
        $html .= '</ul></nav>';
        return $html;
    }
    public function getCurrentPage() { return $this->currentPage; }
    public function getItemsPerPage() { return $this->itemsPerPage; }
}

// ----------- Data Sanitizer -----------
class Sanitizer {
    public static function string($str) {
        return htmlspecialchars(trim($str), ENT_QUOTES, 'UTF-8');
    }
    public static function int($num) {
        return intval($num);
    }
    public static function float($num) {
        return floatval($num);
    }
    public static function email($email) {
        return filter_var($email, FILTER_SANITIZE_EMAIL);
    }
    public static function url($url) {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}

// --------------- NoSQLite ORM ----------------------------------
<?php

use PDO;
use PDOException;

class NoSQLite {
    private ?PDO $pdo = null;
    private string $databasePath;

    /**
     * Constructor: Establishes a connection to the SQLite database.
     *
     * @param array $config An array containing the database path (key: 'database').
     * @throws Exception If database connection fails.
     */
    public function __construct(array $config) {
        $this->databasePath = $config['database'] ?? 'nosqlite.db';
        try {
            $this->pdo = new PDO("sqlite:" . $this->databasePath);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("NoSQLite connection error: " . $e->getMessage());
            throw new Exception("Failed to connect to NoSQLite database: " . $e->getMessage());
        }
    }

    /**
     * Ensures that a collection (table) exists.
     *
     * @param string $collectionName The name of the collection.
     */
    private function ensureCollectionExists(string $collectionName): void {
        $sql = "CREATE TABLE IF NOT EXISTS `$collectionName` (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT
        )";
        $this->pdo->exec($sql);
    }

    /**
     * Creates an index on a specific field within a collection.
     *
     * @param string $collectionName The name of the collection.
     * @param string $field The JSON field to index (e.g., 'user_id', 'name').
     * @return bool True on success, false on failure.
     */
    public function createIndex(string $collectionName, string $field): bool {
        $this->ensureCollectionExists($collectionName);
        $indexName = "idx_" . md5($collectionName . "_" . $field);
        $sql = "CREATE INDEX IF NOT EXISTS `$indexName` ON `$collectionName` (JSON_EXTRACT(data, '$.$field'))";
        try {
            return $this->pdo->exec($sql) !== false;
        } catch (PDOException $e) {
            error_log("NoSQLite create index error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Inserts a single document into a collection.
     *
     * @param string $collectionName The name of the collection.
     * @param array $document The document (associative array) to insert.
     * @return int|null The auto-generated ID of the inserted document, or null on failure.
     */
    public function insertOne(string $collectionName, array $document): ?int {
        $this->ensureCollectionExists($collectionName);
        $jsonData = json_encode($document);
        $stmt = $this->pdo->prepare("INSERT INTO `$collectionName` (data) VALUES (:data)");
        $stmt->bindParam(':data', $jsonData);
        if ($stmt->execute()) {
            return $this->pdo->lastInsertId();
        }
        return null;
    }

    /**
     * Finds one document in a collection based on a filter.
     *
     * @param string $collectionName The name of the collection.
     * @param array $filter An associative array of conditions (field => value). Supports basic equality.
     * @param array $projection Optional array of fields to include or exclude (e.g., ['include' => ['name', 'email'], 'exclude' => ['password']]).
     * @return array|null The found document (as an associative array), or null if not found.
     */
    public function findOne(string $collectionName, array $filter = [], array $projection = []): ?array {
        $results = $this->find($collectionName, $filter, ['limit' => 1, 'projection' => $projection]);
        return $results[0] ?? null;
    }

    /**
     * Finds multiple documents in a collection based on a filter and options.
     *
     * @param string $collectionName The name of the collection.
     * @param array $filter An associative array of conditions (field => value). Supports basic equality.
     * @param array $options An associative array of options:
     * - 'limit' => int,
     * - 'offset' => int,
     * - 'sort' => array (e.g., ['field' => 'name', 'direction' => 'ASC' or 'DESC']),
     * - 'projection' => array (e.g., ['include' => ['name', 'email'], 'exclude' => ['password']]).
     * @return array An array of found documents (associative arrays).
     */
    public function find(string $collectionName, array $filter = [], array $options = []): array {
        $this->ensureCollectionExists($collectionName);
        $whereClauses = [];
        $values = [];
        foreach ($filter as $key => $value) {
            $whereClauses[] = "JSON_EXTRACT(data, '$.$key') = :$key";
            $values[":$key"] = json_encode($value);
        }
        $whereSql = !empty($whereClauses) ? "WHERE " . implode(" AND ", $whereClauses) : "";

        $limitSql = isset($options['limit']) ? "LIMIT " . intval($options['limit']) : "";
        $offsetSql = isset($options['offset']) ? "OFFSET " . intval($options['offset']) : "";
        $orderBySql = '';
        if (isset($options['sort']) && is_array($options['sort']) && isset($options['sort']['field'])) {
            $direction = strtoupper($options['sort']['direction'] ?? 'ASC');
            $orderBySql = "ORDER BY JSON_EXTRACT(data, '$.{$options['sort']['field']}') " . ($direction === 'DESC' ? 'DESC' : 'ASC');
        }

        $sql = "SELECT _id, data FROM `$collectionName` $whereSql $orderBySql $limitSql $offsetSql";
        $stmt = $this->pdo->prepare($sql);
        foreach ($values as $param => $val) {
            $stmt->bindParam($param, $val);
        }
        $stmt->execute();
        $results = $stmt->fetchAll();
        $decodedResults = [];
        foreach ($results as $row) {
            $data = json_decode($row['data'], true);
            if (!empty($projection)) {
                $data = $this->applyProjection($data, $projection);
            }
            $decodedResults[$row['_id']] = $data;
        }
        return array_values($decodedResults); // Return as a simple array of documents
    }

    /**
     * Updates one document in a collection based on a filter.
     *
     * @param string $collectionName The name of the collection.
     * @param array $filter An associative array of conditions to identify the document.
     * @param array $update An associative array of fields to update (will merge with existing data).
     * @return int The number of affected rows (0 or 1).
     */
    public function updateOne(string $collectionName, array $filter, array $update): int {
        $existingDocument = $this->findOne($collectionName, $filter);
        if ($existingDocument) {
            $mergedDocument = array_merge($existingDocument, $update);
            $jsonData = json_encode($mergedDocument);
            $whereClauses = [];
            $values = [];
            foreach ($filter as $key => $value) {
                $whereClauses[] = "JSON_EXTRACT(data, '$.$key') = :$key";
                $values[":$key"] = json_encode($value);
            }
            $whereSql = !empty($whereClauses) ? "WHERE " . implode(" AND ", $whereClauses) : "";

            $sql = "UPDATE `$collectionName` SET data = :data $whereSql";
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':data', $jsonData);
            foreach ($values as $param => $val) {
                $stmt->bindParam($param, $val);
            }
            $stmt->execute();
            return $stmt->rowCount();
        }
        return 0;
    }

    /**
     * Deletes one document from a collection based on a filter.
     *
     * @param string $collectionName The name of the collection.
     * @param array $filter An associative array of conditions to identify the document.
     * @return int The number of affected rows (0 or 1).
     */
    public function deleteOne(string $collectionName, array $filter): int {
        $whereClauses = [];
        $values = [];
        foreach ($filter as $key => $value) {
            $whereClauses[] = "JSON_EXTRACT(data, '$.$key') = :$key";
            $values[":$key"] = json_encode($value);
        }
        $whereSql = !empty($whereClauses) ? "WHERE " . implode(" AND ", $whereClauses) : "";

        $sql = "DELETE FROM `$collectionName` $whereSql LIMIT 1";
        $stmt = $this->pdo->prepare($sql);
        foreach ($values as $param => $val) {
            $stmt->bindParam($param, $val);
        }
        $stmt->execute();
        return $stmt->rowCount();
    }

    /**
     * Applies a projection to a document, selecting or excluding specific fields.
     *
     * @param array $document The document to project.
     * @param array $projection An array with 'include' and/or 'exclude' keys containing arrays of field names.
     * @return array The projected document.
     */
    private function applyProjection(array $document, array $projection): array {
        if (isset($projection['include']) && is_array($projection['include'])) {
            return array_intersect_key($document, array_flip($projection['include']));
        } elseif (isset($projection['exclude']) && is_array($projection['exclude'])) {
            return array_diff_key($document, array_flip($projection['exclude']));
        }
        return $document;
    }

    /**
     * Begins a transaction.
     *
     * @return bool True on success, false on failure.
     */
    public function beginTransaction(): bool {
        return $this->pdo->beginTransaction();
    }

    /**
     * Commits the current transaction.
     *
     * @return bool True on success, false on failure.
     */
    public function commitTransaction(): bool {
        return $this->pdo->commit();
    }

    /**
     * Rolls back the current transaction.
     *
     * @return bool True on success, false on failure.
     */
    public function rollbackTransaction(): bool {
        return $this->pdo->rollBack();
    }

    /**
     * Gets the last insert ID.
     *
     * @return int|null The last inserted ID, or null if no insert has occurred.
     */
    public function lastInsertId(): ?int {
        return $this->pdo->lastInsertId();
    }
}

/** NoSQLite USAGE 
// Key Improvements in this NoSQLite Class:

Constructor: Takes the database configuration upon instantiation.
createIndex(): Allows you to create SQLite indexes on specific JSON fields to potentially improve query performance.
Projection: The findOne() and find() methods now accept a $projection option to include or exclude specific fields from the returned documents.
Sorting: The find() method supports sorting by a specified field and direction (ASC or DESC).
Transactions: Includes beginTransaction(), commitTransaction(), and rollbackTransaction() for managing atomic operations.
More Consistent Return Values: Methods like insertOne(), updateOne(), and deleteOne() return more informative values (ID on insert, number of affected rows on update/delete).
Clearer Error Handling: While still basic, the constructor includes error logging for connection failures. You can expand error handling in other methods as needed.
How to Integrate:

Save as a Separate File: Save this NoSQLite class code as a separate PHP file (e.g., NoSQLite.php) in your project.

Include in Your Framework: In your jogu.php (or wherever you're managing your class loading), include this file.

Instantiate: In your application code (e.g., in your public/index.php or a service provider), you would instantiate NoSQLite with your database configuration:

PHP

<?php
// ... include jogu.php and NoSQLite.php

$app = new Jogu();
$app->config()->load('../config.php');

try {
    $noSqlite = new NoSQLite($app->config()->get('database'));
    // Now you can use $noSqlite to interact with your SQLite NoSQL database
} catch (Exception $e) {
    die("Error initializing NoSQLite: " . $e->getMessage());
}

// ... your routes and application logic
Update Route Handlers: Modify your route handlers to use the methods of the $noSqlite instance (e.g., $noSqlite->insertOne(), $noSqlite->find(), etc.).

This NoSQLite class provides a more feature-rich way to interact with SQLite in a schemaless manner. Remember that while it offers more flexibility than a traditional relational approach, you still need to be mindful of data consistency and the potential performance implications of querying JSON data. You can further extend this class with more advanced querying capabilities and data manipulation as your needs evolve.
*/

// ----------- Database Agnostic NoSQL ORM (JoguNoSQL) -----------
class JoguNoSQL
{
    protected static $pdo;
    protected static $table;
    protected static $indexes = [];

    public $id;
    protected $data = [];

    // --- Connection and Table Setup ---

    public static function connect($dsn, $username = null, $password = null, $options = [])
    {
        static::$pdo = new PDO($dsn, $username, $password, $options);
        static::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public static function setTable($table, $indexes = [])
    {
        static::$table = $table;
        static::$indexes = $indexes;
    }

    public static function initialize()
    {
        $table = static::$table;
        $sql = "CREATE TABLE IF NOT EXISTS `$table` (
            `id` INTEGER PRIMARY KEY AUTO_INCREMENT,
            `data` TEXT NOT NULL
        )";
        // SQLite compatibility: replace AUTO_INCREMENT with AUTOINCREMENT
        if (stripos(static::$pdo->getAttribute(PDO::ATTR_DRIVER_NAME), 'sqlite') !== false) {
            $sql = "CREATE TABLE IF NOT EXISTS `$table` (
                `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                `data` TEXT NOT NULL
            )";
        }
        static::$pdo->exec($sql);

        // Indexes (on JSON fields, not always supported, so skip for full portability)
    }

    // --- CRUD Operations ---

    public function __construct($data = [])
    {
        $this->data = $data;
        if (isset($data['id'])) {
            $this->id = $data['id'];
            unset($this->data['id']);
        }
    }

    public function __get($name)
    {
        return $this->data[$name] ?? null;
    }

    public function __set($name, $value)
    {
        $this->data[$name] = $value;
    }

    public static function findOne($criteria = [])
    {
        $results = static::find($criteria, 1);
        return $results ? $results[0] : null;
    }

    public static function find($criteria = [], $limit = null)
    {
        $table = static::$table;
        $where = [];
        $params = [];
        foreach ($criteria as $key => $value) {
            $where[] = "JSON_EXTRACT(data, '$.$key') = ?";
            $params[] = $value;
        }
        $sql = "SELECT id, data FROM `$table`";
        if ($where) {
            $sql .= " WHERE " . implode(' AND ', $where);
        }
        if ($limit) {
            $sql .= " LIMIT " . intval($limit);
        }
        $stmt = static::$pdo->prepare($sql);
        $stmt->execute($params);
        $results = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $data = json_decode($row['data'], true) ?: [];
            $data['id'] = $row['id'];
            $results[] = new static($data);
        }
        return $results;
    }

    public static function all()
    {
        return static::find();
    }

    public static function count($criteria = [])
    {
        $table = static::$table;
        $where = [];
        $params = [];
        foreach ($criteria as $key => $value) {
            $where[] = "JSON_EXTRACT(data, '$.$key') = ?";
            $params[] = $value;
        }
        $sql = "SELECT COUNT(*) FROM `$table`";
        if ($where) {
            $sql .= " WHERE " . implode(' AND ', $where);
        }
        $stmt = static::$pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn();
    }

    public function save()
    {
        $table = static::$table;
        $json = json_encode($this->data);
        if ($this->id) {
            $sql = "UPDATE `$table` SET data = ? WHERE id = ?";
            $stmt = static::$pdo->prepare($sql);
            $stmt->execute([$json, $this->id]);
        } else {
            $sql = "INSERT INTO `$table` (data) VALUES (?)";
            $stmt = static::$pdo->prepare($sql);
            $stmt->execute([$json]);
            $this->id = static::$pdo->lastInsertId();
        }
    }

    public function delete()
    {
        if (!$this->id) return;
        $table = static::$table;
        $sql = "DELETE FROM `$table` WHERE id = ?";
        $stmt = static::$pdo->prepare($sql);
        $stmt->execute([$this->id]);
        $this->id = null;
    }

    // --- Utility ---

    public function toArray()
    {
        return array_merge(['id' => $this->id], $this->data);
    }

    public function __toString()
    {
        return '<' . static::$table . ' (' . $this->id . '): ' . json_encode($this->data) . '>';
    }
}

/**
JoguNoSQL Usage Example
php
// Connect to MySQL or SQLite
JoguNoSQL::connect('mysql:host=localhost;dbname=testdb', 'user', 'pass');
// JoguNoSQL::connect('sqlite:mydb.sqlite');

// Set table name (and optional indexes)
JoguNoSQL::setTable('users');
JoguNoSQL::initialize();

// Create and save a record
$user = new JoguNoSQL(['name' => 'Alice', 'email' => 'alice@example.com']);
$user->save();

// Find a user
$found = JoguNoSQL::findOne(['email' => 'alice@example.com']);
echo $found;

// Update and save
$found->name = 'Alice Smith';
$found->save();

// Delete
$found->delete();
Key Points:

Uses PDO for maximum portability across MySQL, SQLite, and other databases.

Stores all user data as JSON in a single data column, allowing flexible schema.

Queries use JSON_EXTRACT for MySQL 5.7+/SQLite 3.9+, but you can adjust for older DBs if needed.

Inspired by RedBeanPHP and your Python example, but simplified and portable.

Note: For full compatibility, ensure your MySQL/SQLite version supports JSON functions. For older databases, you may need to adapt the query logic.
**/
class JoguContainer {
    private $services = [];

    public function set($name, $resolver) {
        $this->services[$name] = $resolver;
    }

    public function get($name) {
        if (!isset($this->services[$name])) {
            throw new Exception("Service {$name} not found in container.");
        }
        $resolver = $this->services[$name];
        return $resolver($this); // Pass the container itself for nested dependencies
    }
}

/**
 * Example Usage:
 *
 * $container = new JoguContainer();
 * $container->set('logger', function () { return new Logger(); });
 * $container->set('config', function () { return Config::getInstance(); });
 *
 * // Access:
 * $logger = $container->get('logger');
 * $config = $container->get('config');
 */


class JoguTest {

    public function __construct() {
    }

    public function assertTrue($condition, $message = 'Assertion failed') {
        if ($condition !== true) {
            $this->fail($message);
        }
        echo "<p style='color:green;'>PASSED: $message</p>";
    }

    public function assertFalse($condition, $message = 'Assertion failed') {
        if ($condition !== false) {
            $this->fail($message);
        }
        echo "<p style='color:green;'>PASSED: $message</p>";
    }

    public function assertEquals($expected, $actual, $message = 'Assertion failed') {
        if ($expected != $actual) {
            $this->fail("$message: Expected '$expected', but got '$actual'");
        }
        echo "<p style='color:green;'>PASSED: $message</p>";
    }

    public function assertNotEquals($expected, $actual, $message = 'Assertion failed') {
        if ($expected == $actual) {
            $this->fail("$message: Expected not to be '$expected', but it was.");
        }
        echo "<p style='color:green;'>PASSED: $message</p>";
    }

    public function assertEmpty($actual, $message = 'Assertion failed') {
        if (!empty($actual)) {
            $this->fail("$message: Expected empty, but it was not.");
        }
        echo "<p style='color:green;'>PASSED: $message</p>";
    }

    public function assertNotEmpty($actual, $message = 'Assertion failed') {
        if (empty($actual)) {
            $this->fail("$message: Expected not empty, but it was.");
        }
        echo "<p style='color:green;'>PASSED: $message</p>";
    }

    protected function fail($message) {
        echo "<p style='color:red;'>FAILED: $message</p>";
        exit(1); // Stop execution on failure.  Consider throwing an exception instead for more flexibility.
    }
}

/**
 * Example Usage:
 *
 * $test = new JoguTest();
 *
 * $test->assertEquals(5, 2 + 3, 'Test addition');
 * $test->assertTrue(true, 'Test true');
 */

/** EOF -Kesh Out : ENJOY :) */
/**
                            ##############################                       
                        ##################################                       
                     #####################################                       
                    ######################################                       
                  ##################              ########                       
                 ###########                      ########                       
                ##########                        ########                       
               #########   #######                ########                       
              #########    #######               #############                   
             #########     #######               #################               
             ########       #####               #####################            
             ########                          #########################         
             ########     ########            ############################       
            #########   ##########          ############    ################     
            ########   ###########       #############          #############    
            ######################    ##############               ###########   
            #######################################                  ##########  
     ############################################                     ########## 
    ##########################################                         ##########
    #######################################                             #########
    ##################   #############                                   ########
    ################     #########                                       ########
            ########     #########                                       ########
            ########     #########                                       ########
            ########     #########               ##########              ########
#######     ########     #########           #################           ########
########    ########     #########         #####################         ########
#########  #########     #########       ########################        ########
####################     #########      ##########################       ########
####################     #########      ##########       ##########      ########
  ################       ########################         #######################
    ############         #######################           ######################
       #######           #######################            #####################
                         #######################            #####################
                         #######################            #####################

*/
/** Thank You יהוה */��2"file:///d:/@KESH/windsurf/jogu.php
