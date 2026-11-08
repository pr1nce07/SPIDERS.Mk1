// Leaflet map with vehicle, track, home, anomaly and incident layers.
// Tiles are optional: if the tile server is unreachable (offline field use) a
// neutral grid is shown and the telemetry layers still render.
import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

export interface MapMarker { lat: number; lon: number; kind: "anomaly" | "incident" | "event"; label: string; onClick?: () => void }

interface Props {
  track: [number, number, number, number][];
  vehicle?: { lat: number; lon: number; heading?: number | null } | null;
  home?: { lat: number; lon: number } | null;
  gpsTrack?: [number, number, number, number][];
  markers?: MapMarker[];
  follow?: boolean;
  height?: number | string;
  cursor?: number | null; // replay/incident time cursor → highlight point
}

const COLORS = { track: "#22c7bd", gps: "#e8a100", anomaly: "#ff8a3d", incident: "#ff5470", event: "#7aa7ff", home: "#3ecf8e" };

export default function MapView({ track, vehicle, home, gpsTrack, markers, follow = true, height = "100%", cursor }: Props) {
  const el = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const layers = useRef<{ track?: L.Polyline; gps?: L.Polyline; veh?: L.Marker; home?: L.CircleMarker; marks?: L.LayerGroup; cur?: L.CircleMarker }>({});
  const [tilesOk, setTilesOk] = useState(true);
  const [autoFollow, setAutoFollow] = useState(follow);
  const fitted = useRef(false);

  useEffect(() => {
    if (!el.current || map.current) return;
    const m = L.map(el.current, { zoomControl: true, attributionControl: false, preferCanvas: true }).setView([12.9716, 77.5946], 15);
    const tiles = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, opacity: 1 });
    let errors = 0;
    tiles.on("tileerror", () => {
      errors++;
      if (errors > 4) setTilesOk(false);
    });
    tiles.addTo(m);
    layers.current.marks = L.layerGroup().addTo(m);
    m.on("dragstart", () => setAutoFollow(false));
    map.current = m;
    const ro = new ResizeObserver(() => m.invalidateSize());
    ro.observe(el.current);
    return () => {
      ro.disconnect();
      m.remove();
      map.current = null;
      layers.current = {};
      fitted.current = false;
    };
  }, []);

  useEffect(() => {
    const m = map.current;
    if (!m) return;
    const pts = track.map((p) => [p[1], p[2]] as [number, number]);
    if (!layers.current.track) layers.current.track = L.polyline(pts, { color: COLORS.track, weight: 2.5, opacity: 0.9 }).addTo(m);
    else layers.current.track.setLatLngs(pts);
    if (gpsTrack?.length) {
      const g = gpsTrack.map((p) => [p[1], p[2]] as [number, number]);
      if (!layers.current.gps) layers.current.gps = L.polyline(g, { color: COLORS.gps, weight: 1.5, dashArray: "4 4", opacity: 0.9 }).addTo(m);
      else layers.current.gps.setLatLngs(g);
    }
    if (!fitted.current && pts.length > 40) {
      m.fitBounds(L.latLngBounds(pts).pad(0.3), { maxZoom: 17 });
      fitted.current = true;
    }
  }, [track, gpsTrack]);

  useEffect(() => {
    const m = map.current;
    if (!m || !vehicle || !isFinite(vehicle.lat)) return;
    const rot = vehicle.heading ?? 0;
    const html = `<img class="uav-icon" src="/brand/spider-mask-128.png" alt="Vehicle" style="width:28px;height:28px;object-fit:contain;transform:rotate(${rot}deg);filter:drop-shadow(0 1px 2px rgba(0,0,0,.75))"/>`;
    const icon = L.divIcon({ html, className: "", iconSize: [28, 28], iconAnchor: [14, 14] });
    if (!layers.current.veh) layers.current.veh = L.marker([vehicle.lat, vehicle.lon], { icon, zIndexOffset: 1000 }).addTo(m);
    else {
      layers.current.veh.setLatLng([vehicle.lat, vehicle.lon]);
      layers.current.veh.setIcon(icon);
    }
    if (autoFollow) m.panTo([vehicle.lat, vehicle.lon], { animate: false });
  }, [vehicle?.lat, vehicle?.lon, vehicle?.heading, autoFollow]);

  useEffect(() => {
    const m = map.current;
    if (!m || !home) return;
    if (!layers.current.home) layers.current.home = L.circleMarker([home.lat, home.lon], { radius: 6, color: COLORS.home, weight: 2, fillOpacity: 0.2 }).bindTooltip("HOME").addTo(m);
    else layers.current.home.setLatLng([home.lat, home.lon]);
  }, [home?.lat, home?.lon]);

  useEffect(() => {
    const g = layers.current.marks;
    if (!g) return;
    g.clearLayers();
    (markers || []).forEach((mk) => {
      const c = L.circleMarker([mk.lat, mk.lon], { radius: mk.kind === "incident" ? 8 : 5, color: COLORS[mk.kind], weight: 2, fillOpacity: mk.kind === "incident" ? 0.35 : 0.6 })
        .bindTooltip(mk.label);
      if (mk.onClick) c.on("click", mk.onClick);
      c.addTo(g);
    });
  }, [markers]);

  useEffect(() => {
    const m = map.current;
    if (!m) return;
    if (cursor == null || !track.length) {
      layers.current.cur?.remove();
      layers.current.cur = undefined;
      return;
    }
    let best = track[0];
    for (const p of track) if (Math.abs(p[0] - cursor) < Math.abs(best[0] - cursor)) best = p;
    if (!layers.current.cur) layers.current.cur = L.circleMarker([best[1], best[2]], { radius: 7, color: "#fff", weight: 2, fillColor: COLORS.incident, fillOpacity: 0.9 }).addTo(m);
    else layers.current.cur.setLatLng([best[1], best[2]]);
  }, [cursor, track]);

  return (
    <div className="map" style={{ height }}>
      <div ref={el} style={{ position: "absolute", inset: 0, backgroundImage: tilesOk ? undefined : "linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px)", backgroundSize: "40px 40px" }} />
      {!tilesOk && <div className="map-note muted">Map tiles unavailable (offline) — telemetry layers only</div>}
      {!autoFollow && vehicle && (
        <button className="btn sm" style={{ position: "absolute", zIndex: 500, left: 50, top: 10 }} onClick={() => setAutoFollow(true)}>Follow UAV</button>
      )}
      <div className="map-legend">
        <span><i style={{ background: COLORS.track }} />EKF track</span>
        {gpsTrack?.length ? <span><i style={{ background: COLORS.gps }} />GPS track</span> : null}
        {home ? <span><i style={{ background: COLORS.home }} />Home</span> : null}
        {markers?.some((m) => m.kind === "incident") ? <span><i style={{ background: COLORS.incident }} />Incident</span> : null}
        {markers?.some((m) => m.kind === "anomaly") ? <span><i style={{ background: COLORS.anomaly }} />Anomaly</span> : null}
        <span className="muted">Geofence/mission: N/A unless reported</span>
      </div>
    </div>
  );
}
