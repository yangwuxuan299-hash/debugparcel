export const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; connect-src 'self'; img-src 'self' blob: data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; worker-src 'self' blob:",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

export const IMMUTABLE_ASSET_CACHE =
  "public, max-age=31536000, immutable";

export function isStaticAssetRead(pathname: string, method: string) {
  return (
    pathname.startsWith("/_next/static/") &&
    (method === "GET" || method === "HEAD")
  );
}

export function isCacheableStaticAssetResponse(
  pathname: string,
  method: string,
  status: number,
) {
  return (
    isStaticAssetRead(pathname, method) &&
    ((status >= 200 && status < 300) || status === 304)
  );
}
