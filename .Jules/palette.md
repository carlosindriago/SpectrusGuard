## 2026-01-29 - Decorative Dashicons Pattern
**Learning:** This app frequently uses WordPress `dashicons` for purely decorative visual indicators (like status icons and arrows) without `aria-hidden="true"`. This creates noise for screen reader users.
**Action:** When working on this app, always check `dashicons` usage and apply `aria-hidden="true"` if the icon is decorative or has adjacent text.

## 2026-02-02 - JS-Generated UI & Accessibility
**Learning:** Found a critical bug in `admin.js` where the toast `icon` variable was undefined, causing the UI to crash and fall back to `alert()`. This highlights the risk of unchecked JS-generated UI.
**Action:** When adding or modifying JS-generated components, always verify variables are defined and ensure ARIA attributes (roles, live regions) are injected dynamically.
