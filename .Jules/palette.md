## 2026-01-29 - Decorative Dashicons Pattern
**Learning:** This app frequently uses WordPress `dashicons` for purely decorative visual indicators (like status icons and arrows) without `aria-hidden="true"`. This creates noise for screen reader users.
**Action:** When working on this app, always check `dashicons` usage and apply `aria-hidden="true"` if the icon is decorative or has adjacent text.

## 2026-02-01 - Critical Feedback Bug & Accessibility Fixes
**Learning:** Notification systems must be robust; a missing icon variable broke the entire feedback loop. Also, dynamic content like toasts and charts are invisible to screen readers without ARIA roles.
**Action:** Always check variable scope in JS, and use role="alert" for toasts and role="img" with fallback for canvas elements.
