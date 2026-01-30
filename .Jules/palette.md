## 2026-01-29 - Decorative Dashicons Pattern
**Learning:** This app frequently uses WordPress `dashicons` for purely decorative visual indicators (like status icons and arrows) without `aria-hidden="true"`. This creates noise for screen reader users.
**Action:** When working on this app, always check `dashicons` usage and apply `aria-hidden="true"` if the icon is decorative or has adjacent text.

## 2026-03-01 - Dynamic Button Accessibility
**Learning:** Buttons generated via jQuery in `scanner.js` lacked `aria-label` attributes present in the PHP template, creating an inconsistent accessibility experience for dynamic content vs initial load.
**Action:** When modifying PHP views, always check for corresponding JS render functions to ensure accessibility attributes are mirrored in dynamic content generation.
