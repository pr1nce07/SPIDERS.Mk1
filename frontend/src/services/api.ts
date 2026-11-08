// REST client. Errors come back in the backend's structured error model and are
// surfaced as ApiError (never a raw stack trace).

export class ApiError extends Error {
  status: number;
  body: any;
  constructor(status: number, body: any) {
    super(body?.message || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

function token(): string | null {
  try {
    return localStorage.getItem("pushpak.token");
  } catch {
    return null;
  }
}

async function request<T>(method: string, path: string, body?: any, isForm = false): Promise<T> {
  const headers: Record<string, string> = {};
  const tk = token();
  if (tk) headers["Authorization"] = `Bearer ${tk}`;
  if (body !== undefined && !isForm) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : isForm ? body : JSON.stringify(body) });
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) throw new ApiError(res.status, typeof data === "string" ? { message: data } : data);
  return data as T;
}

export const api = {
  get: <T = any>(p: string) => request<T>("GET", p),
  post: <T = any>(p: string, b?: any) => request<T>("POST", p, b ?? {}),
  put: <T = any>(p: string, b?: any) => request<T>("PUT", p, b ?? {}),
  del: <T = any>(p: string) => request<T>("DELETE", p),
  upload: <T = any>(p: string, form: FormData) => request<T>("POST", p, form, true),
};

export function qs(params: Record<string, any>): string {
  const u = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
  });
  const s = u.toString();
  return s ? `?${s}` : "";
}

export function downloadText(name: string, text: string, mime = "text/plain") {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export function toCSV(rows: Record<string, any>[], cols?: string[]): string {
  if (!rows.length) return "";
  const c = cols || Object.keys(rows[0]);
  const esc = (v: any) => {
    const s = v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [c.join(","), ...rows.map((r) => c.map((k) => esc(r[k])).join(","))].join("\n");
}
