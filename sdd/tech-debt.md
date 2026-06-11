## [2026-06-10] PHPStan WordPress Symbol Resolution Missing
**Archivo**: composer.json
**Problema**: El script `analyze` ejecuta PHPStan sobre `includes/` pero no hay una configuracion visible que cargue stubs/bootstrap de WordPress; como resultado, el analisis reporta miles de falsos positivos por funciones globales y clases de WordPress no resueltas.
**Impacto**: alto
**Sugerencia**: Agregar una configuracion de PHPStan para WordPress (por ejemplo `phpstan.neon` con bootstrap/stubs apropiados) y hacer que `composer run analyze` use esa configuracion para reducir ruido y permitir detectar regresiones reales.
