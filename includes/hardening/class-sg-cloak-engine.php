<?php


if (!defined('ABSPATH')) {
    exit;
}

class Spectrus_Cloak_Engine
{

    // Mapeo de rutas dinámico via get_mappings()

    public function __construct()
    {
        // Solo ejecutar en el frontend para no romper el admin
        if (!is_admin() && !defined('DOING_AJAX')) {
            // Changed from 'init' to 'template_redirect' to capture more output
            add_action('template_redirect', [$this, 'start_buffer']);
        }
    }

    /**
     * Inicia el buffer de salida. Todo lo que WP vaya a imprimir, lo capturamos.
     */
    public function start_buffer()
    {
        // Verifica si la función está activa en opciones
        $settings = get_option('spectrus_shield_settings', []);

        // DEBUG: Verify settings and execution
        /*
        if (isset($_GET['debug_cloak'])) {
            echo "Cloak Debug: Enabled? " . (!empty($settings['url_cloaking_enabled']) ? 'YES' : 'NO');
            exit;
        }
        */

        if (!empty($settings['url_cloaking_enabled'])) {
            ob_start([$this, 'rewrite_html']);
        }
    }

    /**
     * Obtiene el mapa de reemplazos (Configurable por el usuario)
     */
    private function get_mappings()
    {
        // Defaults base
        $defaults = [
            'wp-content/themes' => 'assets/skins',
            'wp-content/uploads' => 'assets/media',
            'wp-includes' => 'core/lib',
            'wp-content/plugins' => 'assets/modules', // Carpeta base de plugins
        ];

        // Obtener mapeos personalizados de plugins (Guardados en DB)
        // Estructura en DB: ['woocommerce' => 'shop-sys', 'elementor' => 'ui-kit']
        $custom_plugins = get_option('sg_cloak_plugin_map', []);

        $plugin_rewrites = [];
        foreach ($custom_plugins as $real => $fake) {
            // OJO: El orden importa. Primero las rutas largas (plugins específicos)
            // luego las rutas cortas (carpeta plugins general).
            $plugin_rewrites["wp-content/plugins/$real"] = "assets/modules/$fake";
        }

        // Fusionar: Primero plugins específicos, luego carpetas generales
        return array_merge($plugin_rewrites, $defaults);
    }

    /**
     * El corazón del camuflaje. Reemplaza rutas en el HTML final.
     */
    public function rewrite_html($buffer)
    {
        if (empty($buffer))
            return $buffer;

        $mappings = $this->get_mappings();

        foreach ($mappings as $original => $new) {
            // Reemplazo simple de string
            $buffer = str_replace($original, $new, $buffer);

            // Escaped Slashes Support (maintained from previous version)
            $buffer = str_replace(
                str_replace('/', '\/', $original),
                str_replace('/', '\/', $new),
                $buffer
            );
        }

        // Limpieza de Clases CSS del BODY (Para evitar 'wp-page', etc)
        // Usamos Regex para limpiar clases específicas dentro de class="..."
        $buffer = preg_replace_callback('/<body([^>]*)class=["\'](.*?)["\']([^>]*)>/', function ($matches) {
            $classes = $matches[2];
            // Filtramos clases que empiecen por wp- (pero cuidado con romper themes)
            // Mejor quitamos las conocidas que delatan versión
            $blacklist = ['wp-custom-logo', 'customize-support', 'wp-embed-responsive'];
            $classes = str_replace($blacklist, '', $classes);
            return "<body{$matches[1]}class=\"$classes\"{$matches[3]}>";
        }, $buffer);

        // 3. Limpieza de comentarios HTML de WP
        $buffer = preg_replace('/<!--.*?-->/s', '', $buffer);

        return $buffer;
    }

    /**
     * DETECTIVE DE SERVIDOR 🕵️‍♂️
     * Analiza el entorno para saber qué reglas generar.
     */
    public static function detect_server_environment()
    {
        $server_software = $_SERVER['SERVER_SOFTWARE'] ?? '';

        if (stripos($server_software, 'apache') !== false || stripos($server_software, 'litespeed') !== false) {
            return 'apache';
        } elseif (stripos($server_software, 'nginx') !== false) {
            return 'nginx';
        } elseif (stripos($server_software, 'iis') !== false) {
            return 'iis';
        }

        return 'unknown';
    }

    /**
     * Verifica si las reglas ya están escritas en .htaccess
     */
    public static function htaccess_has_rules()
    {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path)) {
            return false;
        }

        $content = file_get_contents($htaccess_path);

        // insert_with_markers usa este formato
        return strpos($content, '# BEGIN SpectrusGuard Cloak') !== false; // Fixed: Matches user provided string used in insert_with_markers (usually removes space?) - sticking to WP standard or previous
    }

    // Note: insert_with_markers uses # BEGIN $name ... so if name is SpectrusGuardCloak it works.

    /**
     * ACTUALIZADO: Generador de Reglas Apache Dinámico
     */
    public static function generate_apache_rules()
    {
        $engine = new self(); // Instancia temporal para acceder a mappings
        $mappings = $engine->get_mappings();

        $rules = "<IfModule mod_rewrite.c>\n";
        $rules .= "RewriteEngine On\n";

        foreach ($mappings as $real => $fake) {
            // Convertimos ruta real a ruta fake para el RewriteRule
            // Lógica inversa: Cuando entra FAKE, sirve REAL.
            // Regla: RewriteRule ^fake/(.*) real/$1 [L,QSA]
            $rules .= "RewriteRule ^{$fake}/(.*) {$real}/$1 [L,QSA]\n";
        }

        $rules .= "</IfModule>\n";

        return $rules;
    }

    /**
     * Generador de Reglas para NGINX
     * Nginx no soporta .htaccess, el usuario debe copiar esto manualmente.
     */
    public static function generate_nginx_rules()
    {
        $rules = "# SpectrusGuard Cloak Rules (Add to server block)\n";

        $rules .= "location /content/skins/ { rewrite ^/content/skins/(.*)$ /wp-content/themes/$1 break; }\n";
        $rules .= "location /content/modules/ { rewrite ^/content/modules/(.*)$ /wp-content/plugins/$1 break; }\n";
        $rules .= "location /content/media/ { rewrite ^/content/media/(.*)$ /wp-content/uploads/$1 break; }\n";
        $rules .= "location /core/lib/ { rewrite ^/core/lib/(.*)$ /wp-includes/$1 break; }\n";

        // Plugins específicos
        $rules .= "location /content/modules/ui-builder/ { rewrite ^/content/modules/ui-builder/(.*)$ /wp-content/plugins/elementor/$1 break; }\n";
        $rules .= "location /content/modules/shop-core/ { rewrite ^/content/modules/shop-core/(.*)$ /wp-content/plugins/woocommerce/$1 break; }\n";
        $rules .= "location /content/modules/forms/ { rewrite ^/content/modules/forms/(.*)$ /wp-content/plugins/contact-form-7/$1 break; }\n";
        $rules .= "location /content/modules/meta-engine/ { rewrite ^/content/modules/meta-engine/(.*)$ /wp-content/plugins/yoast-seo/$1 break; }\n";

        return $rules;
    }
}
