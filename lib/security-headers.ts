export const ROUTED_ASSET_PREFIX = "/__debugparcel_assets";

const NEXT_STATIC_PREFIX = "/_next/static/";
const ROUTED_STATIC_PREFIX = `${ROUTED_ASSET_PREFIX}${NEXT_STATIC_PREFIX}`;

export function staticAssetStoragePath(pathname: string) {
  if (pathname.startsWith(NEXT_STATIC_PREFIX)) return pathname;
  if (pathname.startsWith(ROUTED_STATIC_PREFIX)) {
    return pathname.slice(ROUTED_ASSET_PREFIX.length);
  }
  return null;
}

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
    staticAssetStoragePath(pathname) !== null &&
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
