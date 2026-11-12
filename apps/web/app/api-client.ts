import { demoMode } from "./demo-mode";

type Method = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

export async function api<T>(
  path: string,
  options?: { method?: Method; body?: unknown; fallback?: string },
): Promise<T> {
  const method = options?.method ?? "GET";
  if (demoMode) {
    const { demoRequest } = await import("./demo-api");
    return demoRequest<T>(path, method, options?.body);
  }
  const response = await fetch(`/api${path}`, {
    method,
    ...(options?.body !== undefined
      ? {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(options.body),
        }
      : {}),
  });
  if (!response.ok) {
    const data = (await response.json().catch(() => null)) as {
      detail?: unknown;
    } | null;
    const detail = data?.detail;
    const fallback =
      options?.fallback ??
      `Request failed (${response.status}). Check that the API is running.`;
    throw new Error(
      typeof detail === "string"
        ? detail
        : fallback.replaceAll("{status}", String(response.status)),
    );
  }
  return response.json() as Promise<T>;
}
