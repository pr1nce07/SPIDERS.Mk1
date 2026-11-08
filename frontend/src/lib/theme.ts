// Light / dark / system theme. Stored per browser; applied as <html data-theme>.
import { useSyncExternalStore } from "react";

export type ThemePref = "light" | "dark" | "system";
const KEY = "spiders.theme";
const subs = new Set<() => void>();
const mq = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: dark)") : null;

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY) || localStorage.getItem("pushpak.theme");
    return v === "dark" || v === "light" || v === "system" ? v : "light";
  } catch {
    return "light";
  }
}

let pref: ThemePref = readPref();

export function resolved(p: ThemePref = pref): "light" | "dark" {
  return p === "system" ? (mq?.matches ? "dark" : "light") : p;
}

function apply() {
  const t = resolved();
  document.documentElement.dataset.theme = t;
  // Browser chrome / mobile status bar follows the app theme, not just the OS one.
  document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute("content", t === "dark" ? "#07111f" : "#ffffff"));
  subs.forEach((f) => f());
}

export function setTheme(p: ThemePref) {
  pref = p;
  try {
    localStorage.setItem(KEY, p);
  } catch {
    /* storage unavailable: still applies for this tab */
  }
  apply();
}

export function initTheme() {
  const q = new URLSearchParams(location.search).get("theme");  // e.g. ?theme=dark for kiosk/screenshots
  if (q === "light" || q === "dark" || q === "system") pref = q;
  apply();
  mq?.addEventListener("change", () => pref === "system" && apply());
}

export function useThemePref(): ThemePref {
  return useSyncExternalStore((f) => (subs.add(f), () => subs.delete(f)), () => pref);
}

export function useTheme(): "light" | "dark" {
  return useSyncExternalStore((f) => (subs.add(f), () => subs.delete(f)), () => resolved());
}
