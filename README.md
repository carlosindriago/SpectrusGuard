# GhostShield: Advanced WAF & Stealth Security Suite

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-5.8%2B-green.svg)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-orange.svg)

**Sistema de seguridad integral** que intercepta ataques antes de que toquen tu web y camufla tu sitio para que los hackers ni siquiera sepan que usas WordPress.

## 🛡️ Características

### Web Application Firewall (WAF)
- ⚡ **MU-Plugin DROP-IN**: Se ejecuta ANTES de cargar WordPress
- 🔒 Protección contra **SQL Injection**, **XSS**, **RCE**, **Path Traversal**, **LFI**
- 📋 Reglas Regex actualizables en `rules.json`
- 🔄 Decodificación multi-capa para detectar evasión de filtros
- 📊 Logging detallado con rotación automática

### Ghost Stealth (Anti-Fingerprinting)
- 🕵️ Elimina meta tags reveladores (`<meta name="generator">`)
- 🔇 Limpia cabeceras HTTP (`X-Powered-By`, `Server`)
- 🎭 Oculta versiones en CSS/JS (`?ver=X.X`)
- 🚫 Bloquea XML-RPC y pingbacks
- 🔐 Opción de ocultar `/wp-login.php` con slug personalizado

### API Guard
- 🛑 Bloquea enumeración de usuarios vía REST API
- 🍯 **Honeypot** en el formulario de login
- ⏱️ Limitación de intentos de login
- 📝 Logging de bots y ataques

### Dashboard Enterprise
- 🖥️ **Hero Section Unificado**: Estado de seguridad visual y escáner en un solo panel.
- 📊 **Threat Intel Grid**: Métricas de ataques con sparklines y colores semánticos.
- 🌙 **Professional Dark Mode**: Tema oscuro estilo SaaS (Slate/Blue).
- 🖱️ **Sidebar Inteligente**: Acceso rápido y modo rescate compacto.
- 📈 Gráfico de actividad interactivo con gradientes.

## 📦 Instalación

1. Sube la carpeta `GhostShield` a `/wp-content/plugins/`
2. Activa el plugin en **Plugins > Installed Plugins**
3. El MU-Plugin se instala automáticamente en `wp-content/mu-plugins/`
4. Configura en **GhostShield > Settings**

## ⚙️ Configuración

### Rescue Mode (Fail-Safe)
Si te bloqueas a ti mismo, usa la URL de rescate:
```
https://tusitio.com/?ghost_rescue=TU_CLAVE_SECRETA
```

La clave se genera automáticamente y está disponible en **GhostShield > Dashboard**.

### Whitelist de IPs
Agrega IPs que nunca serán bloqueadas en **Settings > IP Whitelist**.

### Ocultar Login
1. Activa "Hide Login Page" en Settings
2. Define tu slug personalizado (ej: `mi-acceso-secreto`)
3. Accede a tu login en `https://tusitio.com/mi-acceso-secreto`

## 📂 Estructura del Proyecto

```
ghost-shield/
├── ghost-shield.php            # Bootstrapper principal
├── uninstall.php               # Limpieza al desinstalar
├── assets/
│   ├── css/admin.css           # Estilos del dashboard (Dark Mode)
│   └── js/admin.js             # JavaScript admin
├── includes/
│   ├── class-gs-loader.php     # Orquestador Singleton
│   ├── class-gs-logger.php     # Sistema de logging
│   ├── waf/
│   │   ├── class-gs-firewall.php  # Motor WAF
│   │   └── rules.json          # Reglas Regex
│   ├── hardening/
│   │   ├── class-gs-stealth.php   # Anti-fingerprinting
│   │   └── class-gs-api-guard.php # Protección REST API
│   ├── scanner/
│   │   └── class-gs-scanner.php   # Motor de escaneo
│   └── admin/
│       └── class-gs-admin.php  # Dashboard Enterprise
├── mu-loader/
│   └── ghost-waf.php           # DROP-IN para mu-plugins
└── languages/                  # Traducciones
```

## 🔧 Patrones de Diseño

- **Singleton**: `GS_Loader` - Única instancia del orquestador
- **Factory**: `GS_Firewall` - Crea matchers según tipo de ataque
- **Observer**: Hooks para alertas y notificaciones

## 🔐 Mejores Prácticas de Seguridad

El código sigue las mejores prácticas de WordPress:

- ✅ `esc_html()`, `esc_attr()` para escape de output
- ✅ `sanitize_text_field()` para sanitización de input
- ✅ `wp_verify_nonce()` en todas las llamadas AJAX
- ✅ `current_user_can('manage_options')` para capability checks
- ✅ Prepared statements para consultas DB

## 📋 Roadmap

- [x] **Sprint 1**: WAF & MU-Plugin Core
- [x] **Sprint 2**: Hardening & Stealth
- [x] **Sprint 3**: Scanner de Integridad & Malware
- [x] **Sprint 4**: URL Cloaking & Advanced Features
- [x] **Sprint 5**: Enterprise UI/UX Overhaul (Dashboard Redesign)

## 📄 Licencia

GPL v2 o posterior. Consulta [LICENSE](LICENSE) para más detalles.

## 👨‍💻 Autor

Desarrollado por Carlos Developer

---

**⚠️ Nota**: Este plugin está diseñado para sitios en producción. Siempre mantén un backup y prueba en staging primero.
