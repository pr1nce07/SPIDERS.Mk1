// Hash router + global UI state (drawers). Deep links such as
// #/incidents/INC-2026-000001 or #/packets?session=…&idx=… are shareable.
import { useSyncExternalStore } from "react";

export interface Route { page: string; id?: string; query: URLSearchParams }

function parse(): Route {
  const h = location.hash.replace(/^#\/?/, "");
  const [path, q] = h.split("?");
  const [page, id] = path.split("/");
  return { page: page || "dashboard", id: id ? decodeURIComponent(id) : undefined, query: new URLSearchParams(q || "") };
}

let route = parse();
const subs = new Set<() => void>();
window.addEventListener("hashchange", () => {
  route = parse();
  subs.forEach((f) => f());
});

export function useRoute(): Route {
  return useSyncExternalStore((f) => (subs.add(f), () => subs.delete(f)), () => route);
}

export function go(path: string) {
  location.hash = `#/${path.replace(/^\/?#?\/?/, "")}`;
}

// -------------------------------------------------------------- UI drawers
export type DrawerState =
  | { kind: "result"; id: string; data?: any }
  | { kind: "packet"; session: string; idx: number }
  | { kind: "detector"; group: string }
  | { kind: "connect" }
  | null;

let drawer: DrawerState = null;
const dsubs = new Set<() => void>();
export function openDrawer(d: DrawerState) {
  drawer = d;
  dsubs.forEach((f) => f());
}
export function useDrawer(): DrawerState {
  return useSyncExternalStore((f) => (dsubs.add(f), () => dsubs.delete(f)), () => drawer);
}

// -------------------------------------------------------------- UI mode
export type Mode = "OPERATOR" | "INVESTIGATOR" | "ENGINEER";
let mode: Mode = (() => {
  try {
    return (localStorage.getItem("pushpak.mode") as Mode) || "ENGINEER";
  } catch {
    return "ENGINEER";
  }
})();
const msubs = new Set<() => void>();
export function setMode(m: Mode) {
  mode = m;
  try {
    localStorage.setItem("pushpak.mode", m);
  } catch {
    /* ignore */
  }
  msubs.forEach((f) => f());
}
export function useMode(): Mode {
  return useSyncExternalStore((f) => (msubs.add(f), () => msubs.delete(f)), () => mode);
}
