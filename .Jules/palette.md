## 2026-01-29 - Decorative Dashicons Pattern
**Learning:** This app frequently uses WordPress `dashicons` for purely decorative visual indicators (like status icons and arrows) without `aria-hidden="true"`. This creates noise for screen reader users.
**Action:** When working on this app, always check `dashicons` usage and apply `aria-hidden="true"` if the icon is decorative or has adjacent text.
