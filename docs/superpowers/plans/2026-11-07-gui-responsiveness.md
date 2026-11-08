# GUI Responsiveness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the live map and dashboard responsive during telemetry updates, and make sure normal startup serves the built frontend.

**Architecture:** Make Leaflet append only newly received track points, rebuilding only when the track resets or changes shape. Reuse one vehicle icon and update its position/rotation in place. Replace broad backdrop blur on card surfaces with solid theme surfaces. Build the ignored frontend bundle from the startup scripts before launching the backend.

**Tech Stack:** React 19, TypeScript, Leaflet, CSS, Vite.

**Spec:** `docs/superpowers/specs/2026-11-07-gui-responsiveness-design.md`

## Global Constraints

- Preserve existing routes, telemetry, map controls, and responsive breakpoints.
- Do not add dependencies or change backend data flow.
- Do not auto-install dependencies; the startup scripts should give a clear setup message when prerequisites are missing.
- Re-enabling follow must recenter the map; heading-only updates must not pan it.
- Backend startup must serve the built UI at `http://127.0.0.1:8600/` after the frontend build completes.

## Review Focus

- Empty track and first point: map remains valid, then displays the first point.
- Appended or batched points: all new points render, without remapping the prior prefix.
- Reset, session change, resync, or truncation: old path is cleared and the new path appears.
- Heading-only vehicle update: icon rotates in place without resetting its DOM or panning.
- Follow mode off and re-enabled: manual map position is preserved while off, then recenters when follow is enabled.

---

### Task 1: Make live map updates incremental

**Files:**
- Modify: `frontend/src/map/MapView.tsx`

**Interfaces:**
- Consumes: existing `MapView` props; `track` is append-only between explicit resets and is capped upstream.
- Produces: no public API change.

- [ ] Keep a ref of the last rendered track length and boundary tuple references. Use `L.Polyline.addLatLng` for appended points when the previous prefix is still present; use `setLatLngs` when the history shrinks or its boundary references change. Record the new boundary after the update.
- [ ] Create the vehicle `L.DivIcon` once. Update its image rotation and marker coordinates in place. Pan when coordinates change or follow is re-enabled, while skipping heading-only pans.
- [ ] Review the empty, append/batched, reset/truncation, heading-only, and follow re-enable paths against the Review Focus above.

### Task 2: Reduce card surface paint work

**Files:**
- Modify: `frontend/src/gradient.css`

**Interfaces:**
- Consumes: existing light/dark theme surface and line tokens.
- Produces: same component classes and layout.

- [ ] Replace broad card/panel `backdrop-filter` rules with opaque theme surfaces and restrained existing borders/shadows. Preserve card hierarchy and the current mobile breakpoints.
- [ ] Keep any blur limited to floating overlays that need separation; retain existing reduced-transparency behavior.

### Task 3: Ensure startup includes the frontend

**Files:**
- Modify: `scripts/start.sh`
- Create: `scripts/start.ps1`
- Modify: `README.md`

**Interfaces:**
- Consumes: existing `.venv` and `frontend/node_modules` installations.
- Produces: backend startup that first runs `npm run build`, plus a documented Windows launch command.

- [ ] Make `scripts/start.sh` resolve the project root from its own path, check for the existing Python environment and frontend dependencies, build the frontend, then launch `backend/run.py`.
- [ ] Add `scripts/start.ps1` with the same build-then-run flow, using `.venv\\Scripts\\python.exe` and `npm.cmd`; stop with clear instructions when prerequisites are missing.
- [ ] Document the one-command Windows production start at `http://127.0.0.1:8600/` and retain the separate Vite development workflow.

### Task 4: Build and check the layouts

**Files:**
- No additional files.

- [ ] Run `npm run build` from `frontend/`; expected result is a clean TypeScript check and Vite production build.
- [ ] Run the platform startup script through its frontend build step; expected result is a generated `frontend/dist/index.html` before the backend starts.
- [ ] Visually check the dashboard and live map at desktop width and a 390 px viewport; confirm the existing two-column-to-single-column behavior and navigation remain usable.
