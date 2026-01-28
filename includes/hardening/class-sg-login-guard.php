<?php

class Spectrus_Login_Guard
{

    public function __construct()
    {
        add_action('init', [$this, 'handle_login_access']);
        add_filter('site_url', [$this, 'filter_login_url'], 10, 4);
        add_filter('wp_redirect', [$this, 'filter_redirects'], 10, 2);
    }

    /**
     * Intercepta la carga de WordPress.
     * Si entran a /wp-login.php -> 404 o Home.
     * Si entran a /mi-acceso-secreto -> Carga el login.
     */
    public function handle_login_access()
    {
        // Obtenemos el slug configurado (Default: 'ghost-access')
        $settings = get_option('spectrus_shield_settings', []);
        $slug = isset($settings['login_slug']) && !empty($settings['login_slug']) ? $settings['login_slug'] : 'ghost-access';
        $request_uri = $_SERVER['REQUEST_URI'];

        // 1. Detectar intento de acceso al Login Viejo
        if (strpos($request_uri, 'wp-login.php') !== false && !is_user_logged_in()) {
            // Si no viene de un logout o acción permitida...
            if (!isset($_GET['action']) || $_GET['action'] !== 'logout') {
                // ... BLOQUEAR
                status_header(404);
                nocache_headers();
                include(get_query_template('404'));
                exit;
            }
        }

        // 1.1 BLOCK WP-ADMIN for non-authenticated users
        // The user wants 'wp-admin' to not redirect to login, but to 404/block if not logged in.
        // strpos check is simple but covers wp-admin/
        if (strpos($request_uri, '/wp-admin') !== false && !is_user_logged_in() && !defined('DOING_AJAX')) {
            // Check if it's admin-ajax or strictly admin view.
            // DOING_AJAX handles admin-ajax.php, but direct access to /wp-admin/ should be blocked.
            status_header(404);
            nocache_headers();
            include(get_query_template('404'));
            exit;
        }

        // 2. Detectar acceso al Nuevo Login
        // Limpiamos la URL para comparar solo el path
        $path = trim(parse_url($request_uri, PHP_URL_PATH), '/');

        if ($path === $slug) {
            // ¡MAGIA! Incluimos el archivo de login original internamente
            // Definimos una constante para saber que es un acceso legítimo
            define('SG_LOGIN_ALLOWED', true);

            // FIX: Declare globals that wp-login.php relies on.
            // Include them in the scope so they are valid when wp-login.php runs.
            global $user_login, $error, $action, $interim_login, $message;
            global $wp_error, $user_identity, $c, $d;

            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Cambia todas las URLs generadas por WP (en emails, menús, etc)
     * para que apunten al nuevo slug.
     */
    public function filter_login_url($url, $path, $scheme)
    {
        if ($path === 'wp-login.php' && $scheme === 'login') {
            $settings = get_option('spectrus_shield_settings', []);
            $slug = isset($settings['login_slug']) && !empty($settings['login_slug']) ? $settings['login_slug'] : 'ghost-access';
            return home_url('/' . $slug);
        }
        return $url;
    }

    /**
     * Corrige redirecciones después del login para que no vuelvan a wp-login.php
     */
    public function filter_redirects($location, $status)
    {
        if (strpos($location, 'wp-login.php') !== false) {
            $settings = get_option('spectrus_shield_settings', []);
            $slug = isset($settings['login_slug']) && !empty($settings['login_slug']) ? $settings['login_slug'] : 'ghost-access';
            return str_replace('wp-login.php', $slug, $location);
        }
        return $location;
    }
}
