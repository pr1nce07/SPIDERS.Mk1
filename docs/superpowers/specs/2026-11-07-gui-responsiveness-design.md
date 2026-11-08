# GUI Responsiveness Design

## Intent
Keep the live ground-control interface responsive while telemetry updates, and retain a clear layout on desktop and narrow screens.

## Current behavior
- `scripts/start.sh` starts only the backend. The backend serves the frontend only when `frontend/dist` exists, and that directory is ignored by Git, so a fresh checkout can start the API without a UI.
- The backend publishes telemetry at up to 10 Hz. New track points are appended to the frontend history.
- `MapView` rebuilds all Leaflet track coordinates and resets the full polyline whenever the history changes. The backend track history is capped at 3,000 points.
- Vehicle updates recreate the Leaflet icon and can pan the map even when only heading changed.
- `gradient.css` applies an 18 px backdrop blur to broad card and panel surfaces.
- Existing dashboard and navigation breakpoints already cover mobile layouts.

## Goals
- Append new track points to the existing Leaflet line; rebuild it on resets, truncation, or replacement.
- Reuse the vehicle marker and icon DOM, update heading in place, and pan when position changes or follow mode is re-enabled; heading-only updates do not pan.
- Remove broad backdrop blur from cards and panels, keeping the current colors, borders, and hierarchy.
- Preserve existing routes, telemetry, map controls, and responsive breakpoints.
- Make the supplied Windows and shell startup scripts build the frontend before starting the backend, so the production UI is present on a fresh checkout after dependencies are installed.

## Non-goals
- No dashboard redesign, new dependencies, or changes to backend data flow.
- No changes to telemetry contents or the operator's information density.

## Approaches considered
1. Map optimization only: lowest visual risk, but leaves the broad blur effect in place.
2. Map optimization, lighter card surfaces, and a startup build step: map/surface scope was selected by the user; the build step was added after the user reported the frontend does not show on startup. This handles the observed paint path and ensures fresh Windows and shell starts serve the UI from one backend URL.
3. Broad restyle or route redesign: wider and less targeted than the observed performance and startup issues.

## Success checks
- Appending a point does not remap all prior points or recreate the vehicle icon.
- Reset or replaced tracks render correctly, and follow mode still tracks a moving vehicle.
- Cards render without broad backdrop blur; existing breakpoints and reduced-motion behavior remain intact.
- Each supplied startup script builds `frontend/dist` before the backend serves the root page.
- Typecheck/build and a visual check at desktop and narrow widths show no functional or layout regression.
