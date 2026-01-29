---
description: Git Flow workflow for SpectrusGuard plugin development
---

# 🔀 Git Flow Estricto para SpectrusGuard

> ⚠️ **REGLA FUNDAMENTAL**: NUNCA hacer cambios directamente en `main` ni en `develop`.

## Estructura de Ramas Permanentes

```
main     ← Solo recibe merges desde develop (producción)
develop  ← Solo recibe merges desde ramas hijas (integración)
```

## Ramas Temporales (Se eliminan después del merge)

| Tipo | Origen | Destino | Propósito |
|------|--------|---------|-----------|
| `feature/*` | develop | develop | Nueva funcionalidad |
| `bugfix/*` | develop | develop | Corrección de bugs |
| `hotfix/*` | main | main + develop | Fix urgente en producción |
| `release/*` | develop | main + develop | Preparar release |

---

## 🚀 Iniciar Trabajo en una Feature

// turbo
```bash
git checkout develop
git pull origin develop
git checkout -b feature/nombre-descriptivo
```

## ✅ Finalizar Feature (Merge a Develop)

```bash
# 1. Asegurar cambios commiteados
git status

# 2. Cambiar a develop y actualizar
git checkout develop
git pull origin develop

# 3. Merge con --no-ff (mantiene historial)
git merge --no-ff feature/nombre-descriptivo -m "feat: descripción del cambio"

# 4. Push a develop
git push origin develop

# 5. OBLIGATORIO: Eliminar rama local
git branch -d feature/nombre-descriptivo

# 6. OBLIGATORIO: Eliminar rama remota (si existe)
git push origin --delete feature/nombre-descriptivo 2>/dev/null || true
```

---

## 🏷️ Crear un Release (Develop → Main)

```bash
# 1. Crear rama release desde develop
git checkout develop
git pull origin develop
git checkout -b release/v1.x.x

# 2. Hacer ajustes (versión, changelog)
# ... commits de preparación ...

# 3. Merge a main
git checkout main
git pull origin main
git merge --no-ff release/v1.x.x -m "release: v1.x.x"
git tag -a v1.x.x -m "Release v1.x.x"
git push origin main --tags

# 4. Merge de vuelta a develop
git checkout develop
git merge --no-ff release/v1.x.x -m "chore: merge release v1.x.x to develop"
git push origin develop

# 5. OBLIGATORIO: Eliminar rama release
git branch -d release/v1.x.x
```

---

## 🔥 Hotfix Urgente (Main → Main + Develop)

```bash
# 1. Crear hotfix desde main
git checkout main
git pull origin main
git checkout -b hotfix/descripcion-fix

# ... hacer el fix ...

# 2. Merge a main
git checkout main
git merge --no-ff hotfix/descripcion-fix -m "hotfix: descripción"
git push origin main

# 3. Merge a develop
git checkout develop
git merge --no-ff hotfix/descripcion-fix -m "hotfix: merge to develop"
git push origin develop

# 4. OBLIGATORIO: Eliminar rama hotfix
git branch -d hotfix/descripcion-fix
```

---

## 📝 Convención de Commits

| Prefijo | Uso |
|---------|-----|
| `feat:` | Nueva funcionalidad |
| `fix:` | Corrección de bugs |
| `hotfix:` | Fix urgente en producción |
| `docs:` | Solo documentación |
| `style:` | Formato (no lógica) |
| `refactor:` | Refactorización |
| `chore:` | Mantenimiento |

---

## ⛔ REGLAS ESTRICTAS

1. **NUNCA** commit directo a `main`
2. **NUNCA** commit directo a `develop`  
3. **SIEMPRE** crear rama hija para cualquier cambio
4. **SIEMPRE** eliminar ramas después del merge
5. **SIEMPRE** usar `--no-ff` en merges
6. Las únicas ramas permanentes son: `main` y `develop`

## 📋 Checklist Pre-Merge

- [ ] Código probado localmente
- [ ] Commits con prefijos correctos
- [ ] Rama actualizada con `develop` (rebase o merge)
- [ ] Rama lista para eliminar post-merge
