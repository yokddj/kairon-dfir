# Frontend Deployment Note

## Current state

The frontend is currently deployed as a **Vite dev server** (`npm run dev`),
not as a production build.  This is a development-oriented deployment.

## Why this is the case

* The `frontend/Dockerfile` runs `CMD ["npm", "run", "dev", ...]`.
* Vite's dev server serves source modules directly from `/app/src/`, with
  on-the-fly transpilation and HMR.
* This is what the project's existing configuration has always been.

## What is exposed

* `http://<host>:5173/` returns the SPA HTML shell.
* `http://<host>:5173/src/App.tsx` and any other `/src/...` path returns
  the JavaScript module source.  Anyone with network access to the
  frontend can read the source.

## What is NOT exposed

* No `dist/` artifacts are produced by the running image.
* The image has `cap_drop: ALL`, `no-new-privileges: true`, and a
  read-only rootfs.
* The frontend has no public network exposure beyond the SPA shell.

## Implications

* A `npm run build` step does succeed (verified in the recovery sprint),
  producing a `dist/` tree, but it is not served by the running image.
* The dev-server deployment is convenient for debugging but exposes the
  source over HTTP.  This is acceptable for a lab/internal network but
  not for public exposure.

## Recommended production sprint (separate)

A future sprint should:

1. Change the frontend `Dockerfile` to:
   * `npm ci` (after committing a lockfile)
   * `npm run build`
   * serve `dist/` via a static server (nginx, caddy, vite preview)
2. Remove the source-mount step from the runtime image.
3. Add CSP, HSTS, and other standard frontend hardening.
4. Configure cache headers for hashed asset chunks.
5. Document the build/serve separation in deploy scripts.

This sprint is **separate** from the Memory UI recovery.  The recovery
preserves the existing `npm run dev` deployment to avoid expanding scope
and to keep the change set auditable.
