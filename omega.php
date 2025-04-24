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
 * Jogu PHP Macro-Frameworks Son called Omega PHP
 * Version: 3.0
 * Start Date: 2025-04-17 03:16 EAT [my eldest sibling Patos Birthday :)]
 * Last Update: 2025-04-24 03:16 EAT [Life Analytics Sign JPN] deployed to GIT/johnmwirigimahugu and Gitlab/johnmwirigimahugu 
 *
 * Omega (Ω) Microframework - A minimalist routing and templating system.
 */
class Ω {
    /** @var array<int, array{method:string, pattern:string, callback:callable}> $routes */
    private array $routes = [];

    /**
     * Register a route with HTTP method and URI pattern (regex).
     * Pattern should be a regex without delimiters, e.g. '^/todo/(\d+)$'
     *
     * @param string $method HTTP method (GET, POST, etc.)
     * @param string $pattern URI pattern as regex (without delimiters)
     * @param callable $callback Callback function to execute for the route
     * @return self For method chaining
     */
    public function addRoute(string $method, string $pattern, callable $callback): self {
        $this->routes[] = [
            'method' => strtoupper($method),
            'pattern' => $pattern,
            'callback' => $callback,
        ];
        return $this;
    }

    /**
     * Shortcut for GET route registration
     *
     * @param string $pattern URI pattern as regex (without delimiters)
     * @param callable $callback Callback function to execute for the route
     * @return self For method chaining
     */
    public function GET(string $pattern, callable $callback): self {
        return $this->addRoute('GET', $pattern, $callback);
    }

    /**
     * Shortcut for POST route registration
     *
     * @param string $pattern URI pattern as regex (without delimiters)
     * @param callable $callback Callback function to execute for the route
     * @return self For method chaining
     */
    public function POST(string $pattern, callable $callback): self {
        return $this->addRoute('POST', $pattern, $callback);
    }

    /**
     * Dispatch the current request to matching route
     *
     * - **Routing Table**: Routes are stored as an array of method, pattern, and callback entries.
     * - **Route Patterns**: Patterns are regex strings (without delimiters), making it explicit and flexible.
     * - **Parameter Extraction**: Uses named capture groups in regex to pass parameters as associative arrays.
     * - **HTTP Method Check**: Routes are matched only if HTTP method matches.
     * - **Error Handling**: Returns 404 if no route matches.
     */
    public function run(): void {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

        foreach ($this->routes as $route) {
            if ($route['method'] !== $method) {
                continue; // Skip if HTTP method doesn't match
            }
            if (preg_match('#' . $route['pattern'] . '#i', $uri, $matches)) {
                // Remove numeric keys from matches, keep only named or numeric keys for params
                $params = array_filter(
                    $matches,
                    fn($key) => !is_int($key),
                    ARRAY_FILTER_USE_KEY
                );
                // Call the route callback with $this and params
                call_user_func($route['callback'], $this, $params);
                return; // Stop after first match
            }
        }
        // No route matched
        http_response_code(404);
        echo "404 Not Found";
    }

    /**
     * Render a PHP view template with optional variables.
     * $viewPath can be absolute or relative.
     *
     * - **View Rendering**: view() accepts full path to view file and variables, throws exception if file missing.
     *
     * @param string $viewPath Path to the view file
     * @param array $vars Variables to pass to the view
     * @return string Rendered view content
     * @throws RuntimeException If view file is not found
     */
    public function view(string $viewPath, array $vars = []): string {
        if (!file_exists($viewPath)) {
            throw new RuntimeException("View file not found: $viewPath");
        }
        extract($vars, EXTR_SKIP);
        ob_start();
        include $viewPath;
        return ob_get_clean();
    }
}

/*
 * Example Usage:
 *
 * - **Method Chaining**: addRoute(), GET(), and POST() return $this for chaining.
 * - **Code Clarity**: Uses typed properties, visibility, and comments.
 *
 * $app = new Ω();
 *
 * $app->GET('^/hello$', function($app) {
 *     echo "Hello World!";
 * });
 *
 * $app->GET('^/user/(?<id>\d+)$', function($app, $params) {
 *     echo "User ID: " . htmlspecialchars($params['id']);
 * });
 *
 * $app->run();
 */
