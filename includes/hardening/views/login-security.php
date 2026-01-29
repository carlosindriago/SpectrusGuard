<?php
/**
 * View: Login Security & 2FA Enforcement
 */

if (!defined('ABSPATH')) {
    die('Direct access forbidden.');
}

$settings = get_option('spectrus_shield_settings', []);
?>

<div class="sg-main-layout">
    
    <!-- LEFT COLUMN: GLOBAL POLICY (ADMIN) -->
    <div class="sg-content-column" style="grid-column: span 12;">
        
        <form method="post" action="options.php" id="sg-login-policy-form">
            <?php settings_fields('spectrus_shield_settings_group'); ?>
            <input type="hidden" name="spectrus_shield_settings[form_context]" value="login">

            <!-- Card 1: Access Control (Hide Login) -->
            <div class="sg-card" style="margin-bottom: 24px;">
                <div class="sg-card-header">
                    <h2><?php esc_html_e('Hide Login Area', 'spectrus-guard'); ?></h2>
                </div>
                <div class="sg-settings-card-body">
                    <div class="sg-control-group">
                        <div class="sg-control-info">
                            <label class="sg-control-label"><?php esc_html_e('Custom Login URL', 'spectrus-guard'); ?></label>
                            <p class="sg-control-desc">
                                <?php esc_html_e('Change the default /wp-login.php slug to something secret.', 'spectrus-guard'); ?>
                            </p>
                        </div>
                        <div class="sg-control-input">
                            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                                <label class="sg-switch" style="margin-right: 12px;">
                                    <input type="checkbox" name="spectrus_shield_settings[hide_login]" value="1" <?php checked($settings['hide_login'] ?? false); ?>>
                                    <span class="sg-slider"></span>
                                </label>
                                <code style="padding: 8px; background: rgba(0,0,0,0.2); border-radius: 4px; color: var(--sg-text-secondary);"><?php echo home_url('/'); ?></code>
                                <input type="text" name="spectrus_shield_settings[login_slug]" 
                                    value="<?php echo esc_attr($settings['login_slug'] ?? 'sg-login'); ?>" 
                                    class="sg-input-text" style="width: 150px;" placeholder="my-secret-entry">
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Card 2: Brute Force Protection -->
            <div class="sg-card" style="margin-bottom: 24px;">
                <div class="sg-card-header">
                    <h2><?php esc_html_e('Brute Force Protection', 'spectrus-guard'); ?></h2>
                </div>
                <div class="sg-settings-card-body">
                    <div class="sg-control-group">
                        <div style="width: 100%; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                            <div>
                                <label class="sg-control-label"><?php esc_html_e('Max Login Attempts', 'spectrus-guard'); ?></label>
                                <p class="description" style="margin-bottom: 8px;"><?php esc_html_e('Attempts allowed before lockout.', 'spectrus-guard'); ?></p>
                                <input type="number" name="spectrus_shield_settings[max_login_attempts]"
                                    value="<?php echo esc_attr($settings['max_login_attempts'] ?? 5); ?>"
                                    class="sg-input-text" style="width: 100px;">
                            </div>
                            <div>
                                <label class="sg-control-label"><?php esc_html_e('Lockout Duration (min)', 'spectrus-guard'); ?></label>
                                <p class="description" style="margin-bottom: 8px;"><?php esc_html_e('How long to block IP after failure.', 'spectrus-guard'); ?></p>
                                <input type="number" name="spectrus_shield_settings[login_lockout_time]"
                                    value="<?php echo esc_attr(intval(($settings['login_lockout_time'] ?? 900) / 60)); ?>"
                                    class="sg-input-text" style="width: 100px;">
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Card 3: Zero-Trust Policy (2FA Enforcement) -->
            <div class="sg-card" style="border-top: 3px solid #3b82f6;">
                <div class="sg-card-header">
                    <h2><?php esc_html_e('Zero-Trust Policy', 'spectrus-guard'); ?></h2>
                </div>
                <div class="sg-settings-card-body">
                    
                    <div class="sg-control-group">
                        <div class="sg-control-info">
                            <label class="sg-control-label"><?php esc_html_e('Enforce 2FA Globally', 'spectrus-guard'); ?></label>
                            <p class="sg-control-desc"><?php esc_html_e('Require Two-Factor Authentication for selected roles.', 'spectrus-guard'); ?></p>
                        </div>
                        <div class="sg-control-input">
                            <label class="sg-switch">
                                <input type="checkbox" name="spectrus_shield_settings[enforce_2fa_global]" value="1" <?php checked($settings['enforce_2fa_global'] ?? false); ?>>
                                <span class="sg-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="sg-control-group" style="display: block; margin-top: 20px;">
                        <label class="sg-control-label" style="display: block; margin-bottom: 12px;"><?php esc_html_e('Enforced Roles', 'spectrus-guard'); ?></label>
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px;">
                            <?php
                            $roles = wp_roles()->get_names();
                            $enforced_roles = $settings['enforce_2fa_roles'] ?? ['administrator']; 
                            foreach ($roles as $role_key => $role_name):
                                ?>
                                <label style="display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); padding: 8px; border-radius: 4px;">
                                    <input type="checkbox" name="spectrus_shield_settings[enforce_2fa_roles][]" value="<?php echo esc_attr($role_key); ?>" 
                                        <?php checked(in_array($role_key, $enforced_roles)); ?>>
                                    <span style="color: var(--sg-text-primary); font-size: 13px;"><?php echo esc_html($role_name); ?></span>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <div class="sg-control-group" style="border-top: 1px solid var(--sg-border); padding-top: 20px; margin-top: 20px;">
                        <div class="sg-control-info">
                            <label class="sg-control-label"><?php esc_html_e('Grace Period', 'spectrus-guard'); ?></label>
                            <p class="sg-control-desc"><?php esc_html_e('Allow users to skip 2FA setup for a few days.', 'spectrus-guard'); ?></p>
                        </div>
                        <div class="sg-control-input" style="display: flex; align-items: center; gap: 10px;">
                             <input type="number" name="spectrus_shield_settings[enforce_2fa_grace]" 
                                value="<?php echo esc_attr($settings['enforce_2fa_grace'] ?? 3); ?>" 
                                class="sg-input-text" style="width: 80px;">
                             <span style="color: var(--sg-text-secondary);">days</span>
                        </div>
                    </div>

                    <div style="margin-top: 24px; text-align: right;">
                        <button type="submit" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span> <?php esc_html_e('Save Policy', 'spectrus-guard'); ?>
                        </button>
                    </div>

                </div>
            </div>
        </form>

        <!-- Card 4: Personal Identity (My 2FA) -->
        <h3 style="margin: 24px 0 16px 0; padding-left: 4px; border-left: 4px solid #3b82f6; color: var(--sg-text-primary);">
            <?php esc_html_e('My Security Profile', 'spectrus-guard'); ?>
        </h3>

        <form method="post" id="sg-personal-2fa-form" style="margin-top: 0;">
             <?php wp_nonce_field('spectrus_save_security', 'spectrus_security_nonce'); ?>
             
             <div class="sg-card">
                 <div class="sg-card-header">
                     <h2><?php esc_html_e('Spectrus Sentinel 2FA', 'spectrus-guard'); ?></h2>
                 </div>
                 <div class="sg-settings-card-body">
                     <!-- Include Content Partial -->
                     <?php include SG_PLUGIN_DIR . 'includes/auth/views/setup-2fa.php'; ?>
                     
                     <!-- Footer with Action -->
                     <div class="sg-card-footer" style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--sg-border); text-align: right;">
                        <button type="submit" class="sg-btn sg-btn-secondary">
                            <span class="dashicons dashicons-lock"></span> <?php esc_html_e('Update My Identity', 'spectrus-guard'); ?>
                        </button>
                     </div>
                 </div>
             </div>
        </form>

    </div>
</div>
