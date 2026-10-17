# CyberSentinel AI — Web Application (`apps/web`)

## Status
Phase 24 frontend foundation implemented with Vite, React, and TypeScript.

## Specification & Responsibilities
- Implements the Web Console specified in `docs/19-UI-UX-SPECIFICATION.md`.
- React single-page application with responsive analyst navigation and API-backed resource views.
- Connects to the backend via `apps/api/` REST endpoints.
- Preserves RBAC boundaries: UI visibility reflects verified user permissions.

## Local development

```powershell
npm install
npm run dev
```

The Vite development server proxies `/api`, `/health`, and `/ready` to
`http://127.0.0.1:8000`. Views render server responses when endpoints are
available and show explicit loading, error, permission, or unavailable states
otherwise. Live response remains visibly disabled by design.
