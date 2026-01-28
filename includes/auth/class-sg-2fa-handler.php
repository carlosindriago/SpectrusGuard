<?php

class Spectrus_2FA_Handler
{

    public function __construct()
    {
        // 1. Interceptar Login
        add_filter('wp_authenticate_user', [$this, 'intercept_login'], 10, 2);

        // 2. Procesar el formulario de 2FA (POST)
        add_action('login_form_spectrus_2fa_verify', [$this, 'process_2fa_verification']);

        // 3. Proteger Acciones Sensibles (Sudo Mode)
        add_action('admin_init', [$this, 'check_sudo_mode_for_sensitive_actions']);
    }

    /**
     * Se ejecuta cuando el usuario/contraseña son correctos.
     * Si tiene 2FA, detenemos el login y mostramos el formulario del código.
     */
    public function intercept_login($user, $password)
    {
        // Si ya hay error, pasamos
        if (is_wp_error($user))
            return $user;

        // ¿Tiene 2FA activado?
        $method = get_user_meta($user->ID, 'spectrus_2fa_method', true); // 'app', 'email' o vacío

        if (!$method)
            return $user; // Pase libre si no configuró 2FA

        // LOGICA DE EMAIL (Si eligió email, enviamos el código ahora)
        if ($method === 'email') {
            $this->send_email_code($user);
        }

        // Crear un token temporal de "Pre-Auth"
        $temp_token = md5($user->ID . time() . 'spectrus_salt');
        set_transient('spectrus_pre_auth_' . $temp_token, $user->ID, 10 * MINUTE_IN_SECONDS);

        // Redirigir a pantalla de verificación (evitando login completo)
        $verify_url = wp_login_url() . '?action=spectrus_2fa_verify&token=' . $temp_token;
        wp_redirect($verify_url);
        exit;
    }

    /**
     * Renderiza y Procesa el formulario de código
     */
    public function process_2fa_verification()
    {
        $token = $_GET['token'] ?? '';
        $user_id = get_transient('spectrus_pre_auth_' . $token);

        if (!$user_id) {
            wp_die('Sesión expirada. Vuelve a iniciar sesión.', 'Error 2FA');
        }

        // Si envió el formulario
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['spectrus_2fa_code'])) {
            $code = sanitize_text_field($_POST['spectrus_2fa_code']);
            $user = get_user_by('id', $user_id);

            if ($this->validate_2fa($user, $code)) {
                // ✅ ÉXITO: Loguear al usuario manualmente
                delete_transient('spectrus_pre_auth_' . $token);

                // Marcar sesión como "Sudo Validated" (para proteger configs)
                wp_set_auth_cookie($user_id, true);
                update_user_meta($user_id, 'spectrus_last_sudo', time());

                wp_safe_redirect(admin_url());
                exit;
            } else {
                $error = "Código incorrecto.";
            }
        }

        // Renderizar Vista (HTML simple)
        // Ensure path is correct relative to this file
        include plugin_dir_path(__FILE__) . 'views/verify-2fa.php';
        exit;
    }

    private function validate_2fa($user, $code)
    {
        $method = get_user_meta($user->ID, 'spectrus_2fa_method', true);

        if ($method === 'app') {
            require_once 'class-sg-totp-engine.php';
            $secret = get_user_meta($user->ID, 'spectrus_2fa_secret', true);
            return Spectrus_TOTP_Engine::verify_code($secret, $code);
        } elseif ($method === 'email') {
            $saved_code = get_transient('spectrus_email_code_' . $user->ID);
            return $saved_code && ($saved_code === $code);
        }
        return false;
    }

    private function send_email_code($user)
    {
        $code = rand(100000, 999999);
        set_transient('spectrus_email_code_' . $user->ID, $code, 5 * MINUTE_IN_SECONDS);

        wp_mail(
            $user->user_email,
            'Tu código de acceso - SpectrusGuard',
            "Tu código de seguridad es: $code. Expira en 5 minutos."
        );
    }

    /**
     * 🔥 MODO SUDO: Protección de Configuraciones Sensibles
     */
    public function check_sudo_mode_for_sensitive_actions()
    {
        global $pagenow;

        // Solo protegemos la página de configuración de SpectrusGuard
        if ($pagenow === 'admin.php' && isset($_GET['page']) && $_GET['page'] === 'spectrus-guard') {

            // Si intenta guardar cambios (POST)
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $last_sudo = get_user_meta(get_current_user_id(), 'spectrus_last_sudo', true);

                // Si pasaron más de 15 minutos desde el último login/verificación
                if (!$last_sudo || (time() - $last_sudo > 900)) {
                    // Detener y pedir código de nuevo
                    wp_die('🔒 <b>Modo Sudo Requerido:</b> Por seguridad, verifica tu identidad nuevamente para cambiar estas configuraciones críticas.');
                    // Aquí idealmente rediriges a una pantalla de re-verificación
                }
            }
        }
    }
}
