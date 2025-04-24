# Omega
Omega Framework: Lightweight PHP MVC for modern apps (RESTful, ORM) and Drupal theme framework (grids, Sass). Symbol: Ω or circuit-inspired "O". Tutorial: Routes, controllers, DB integration.

The Omega Framework encompasses two distinct yet robust tools tailored for different web development needs. First, it refers to a lightweight PHP framework designed for modern web applications, built on MVC architecture and optimized for PHP 8.2+. This version emphasizes modularity, dependency injection, RESTful routing, and ORM integration, making it ideal for developers seeking a minimalist yet powerful backend structure. Second, it represents a responsive Drupal theme framework (3.x/7.x) that simplifies theme creation through grid-driven layouts, mobile-first design principles, and Sass support, catering to frontend designers working within Drupal ecosystems. For GitHub repositories, the Omega symbol (Ω) or a stylized circuit-inspired "O" serves as a fitting emblem, symbolizing modularity and connectivity. A practical tutorial demonstrates how to build a basic PHP application with Omega, covering route configuration, controller-view interactions, and database integration using SQLite/MySQL. Whether for backend logic or frontend theming, Omega provides structured solutions for efficient web development.

# Omega Framework ![Omega Framework](https://img.shields.io/badge/Omega-Framework-8B5BE4?logo=php&logoColor=white)

**Lightweight PHP MVC framework** (RESTful, ORM) and **Drupal theme framework** (grids, Sass). Symbol: Ω or circuit-inspired "O".

---

## To-Do List CRUD Tutorial

### 1. Model (Task.php)
namespace App\Models;
use Omega\Database\Model;

class Task extends Model {
protected string $table = 'tasks';
}

text

### 2. Controller (TaskController.php)
namespace App\Controllers;
use App\Models\Task;

class TaskController {
public function index() {
$tasks = Task::all();
return view('tasks/index', ['tasks' => $tasks]);
}

text
public function create() {
    return view('tasks/create');
}

public function store() {
    Task::create($_POST);
    redirect('/tasks');
}

public function edit($id) {
    $task = Task::find($id);
    return view('tasks/edit', ['task' => $task]);
}

public function update($id) {
    $task = Task::find($id);
    $task->update($_POST);
    redirect('/tasks');
}

public function delete($id) {
    $task = Task::find($id);
    $task->delete();
    redirect('/tasks');
}
}

text

### 3. Routes (config/routes.php)
use Omega\Routing\Router;

$router = new Router();
$router->get('/tasks', 'TaskController@index');
$router->get('/tasks/create', 'TaskController@create');
$router->post('/tasks', 'TaskController@store');
$router->get('/tasks/{id}/edit', 'TaskController@edit');
$router->post('/tasks/{id}', 'TaskController@update');
$router->get('/tasks/{id}/delete', 'TaskController@delete');

text

### 4. Views
Create these files in `app/Views/tasks/`:
- **index.php**: Display tasks list with edit/delete links
- **create.php**: Task creation form
- **edit.php**: Pre-filled edit form

---

## Resources
- **PHP Framework**: [Packagist](https://packagist.org/packages/omegamvc/omega)  
- **Drupal Theme**: [Drupal Docs](https://www.drupal.org/docs/7/themes/omega)  
- **Tutorial Code**: [GitHub Template](https://github.com/new?template_name=omega-framework&template_owner=yourusername)
