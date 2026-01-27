---
description: Git Flow workflow for SpectrusGuard plugin development
---

# Git Flow Workflow

Este workflow define cómo trabajar con ramas en SpectrusGuard.

## Estructura de Ramas

```
main                    ← Producción estable (solo releases)
└── develop             ← Integración continua
    └── feature/*       ← Features en desarrollo (temporales)
    └── release/*       ← Preparación de release (temporales)
    └── hotfix/*        ← Fixes urgentes en producción (temporales)
```

## Crear una Feature

```bash
# Asegurarse de estar en develop actualizado
git checkout develop
git pull origin develop

# Crear rama de feature
git checkout -b feature/nombre-descriptivo
```

## Finalizar una Feature

```bash
# Asegurarse de que todo está commiteado
git status

# Cambiar a develop
git checkout develop

# Merge de la feature (con --no-ff para mantener historial)
git merge --no-ff feature/nombre-descriptivo -m "feat: Merge feature/nombre-descriptivo"

# IMPORTANTE: Eliminar la rama feature
git branch -d feature/nombre-descriptivo

# Si la rama estaba en remote, eliminarla también
# // turbo
git push origin --delete feature/nombre-descriptivo
```

## Crear un Release

```bash
git checkout develop
git checkout -b release/v1.x.x

# Hacer ajustes de versión, changelog, etc.
# Cuando esté listo:

git checkout main
git merge --no-ff release/v1.x.x -m "release: v1.x.x"
git tag -a v1.x.x -m "Release v1.x.x"

git checkout develop
git merge --no-ff release/v1.x.x -m "chore: Merge release/v1.x.x back to develop"

# Eliminar rama de release
git branch -d release/v1.x.x
```

## Convención de Commits

| Prefijo     | Uso                          |
|-------------|------------------------------|
| `feat:`     | Nueva funcionalidad          |
| `fix:`      | Corrección de bugs           |
| `docs:`     | Solo documentación           |
| `style:`    | Formato (no afecta lógica)   |
| `refactor:` | Refactorización de código    |
| `test:`     | Agregar o corregir tests     |
| `chore:`    | Mantenimiento, dependencias  |

## Reglas Importantes

1. **NUNCA** hacer push directo a `main`
2. **SIEMPRE** eliminar ramas después de merge
3. **SIEMPRE** usar `--no-ff` en merges para mantener historial
4. Los commits deben ser atómicos y descriptivos
