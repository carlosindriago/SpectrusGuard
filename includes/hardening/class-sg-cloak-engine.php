<?php


if (!defined('ABSPATH')) {
    exit;
}

class Spectrus_Cloak_Engine
{

    // Mapeo de rutas (Esto podría venir de la DB para ser personalizable)
    private $replacements = [
        'wp-content/themes' => 'content/skins',
        'wp-content/plugins' => 'content/modules',
        'wp-content/uploads' => 'content/media',
        'wp-includes' => 'core/lib',
        'wp-content' => 'content', // Fallback
    ];

    // Mapeo específico para ofuscar plugins famosos (Anti-Detector)
    private $plugin_obfuscation = [
        'elementor' => 'ui-builder',
        'woocommerce' => 'shop-core',
        'contact-form-7' => 'forms',
        'yoast-seo' => 'meta-engine'
    ];

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
     * El corazón del camuflaje. Reemplaza rutas en el HTML final.
     */
    public function rewrite_html($buffer)
    {
        if (empty($buffer))
            return $buffer;

        // DEBUG: Uncomment to trace execution
        // file_put_contents(WP_CONTENT_DIR . '/sg_cloak_log.txt', "Rewriting output " . strlen($buffer) . " chars\n", FILE_APPEND);

        // 1. Reemplazo de Rutas Base (Normal y Escaped Slashes)
        foreach ($this->replacements as $original => $new) {
            // Normal: wp-content/themes -> content/skins
            $buffer = str_replace($original, $new, $buffer);

            // Escaped (JSON/JS): wp-content\/themes -> content\/skins
            // We escape the slash for the replacement simply by checking usage
            $buffer = str_replace(
                str_replace('/', '\/', $original),
                str_replace('/', '\/', $new),
                $buffer
            );
        }

        // 2. Ofuscación Específica de Plugins
        foreach ($this->plugin_obfuscation as $real_name => $fake_name) {
            // Normal
            $buffer = str_replace("modules/$real_name", "modules/$fake_name", $buffer); // Already rewritten wp-content/plugins to modules

            // Escaped
            $buffer = str_replace("modules\/$real_name", "modules\/$fake_name", $buffer);

            // Handle edge case where it might still be wp-content/plugins/... if skipped above (redundant but safe)
            // Note: The first loop should have mostly handled the prefix.
        }

        // 3. Limpieza de comentarios HTML de WP
        // Elimina <!-- /wp:paragraph --> y similares
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
        return strpos($content, '# BEGIN SpectrusGuardCloak') !== false;
    }

    /**
     * Generador de Reglas para APACHE (.htaccess)
     * Estas reglas son necesarias para que las nuevas URLs funcionen.
     */
    public static function generate_apache_rules()
    {
        $rules = "<IfModule mod_rewrite.c>\n";
        $rules .= "RewriteEngine On\n";

        // Reglas para rutas base
        $rules .= "RewriteRule ^content/skins/(.*) wp-content/themes/$1 [L,QSA]\n";
        $rules .= "RewriteRule ^content/modules/(.*) wp-content/plugins/$1 [L,QSA]\n";
        $rules .= "RewriteRule ^content/media/(.*) wp-content/uploads/$1 [L,QSA]\n";
        $rules .= "RewriteRule ^core/lib/(.*) wp-includes/$1 [L,QSA]\n";

        // Reglas para plugins específicos (Deben ir ANTES de las generales)
        // Ejemplo: content/modules/ui-builder -> wp-content/plugins/elementor
        $rules .= "RewriteRule ^content/modules/ui-builder/(.*) wp-content/plugins/elementor/$1 [L,QSA]\n";
        $rules .= "RewriteRule ^content/modules/shop-core/(.*) wp-content/plugins/woocommerce/$1 [L,QSA]\n";
        // Agregar el resto
        $rules .= "RewriteRule ^content/modules/forms/(.*) wp-content/plugins/contact-form-7/$1 [L,QSA]\n";
        $rules .= "RewriteRule ^content/modules/meta-engine/(.*) wp-content/plugins/yoast-seo/$1 [L,QSA]\n";

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
