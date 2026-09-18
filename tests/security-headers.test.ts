import assert from "node:assert/strict";
import test from "node:test";

const securityHeadersModuleUrl = new URL(
  "../lib/security-headers.ts",
  import.meta.url,
).href;
const { isCacheableStaticAssetResponse, isStaticAssetRead } = await import(
  securityHeadersModuleUrl
) as typeof import("../lib/security-headers");

test("only successful read requests for built assets receive immutable caching", () => {
  const asset = "/_next/static/chunks/app-content-hash.js";

  assert.equal(isStaticAssetRead(asset, "GET"), true);
  assert.equal(isStaticAssetRead(asset, "HEAD"), true);
  assert.equal(isStaticAssetRead(asset, "POST"), false);
  assert.equal(isStaticAssetRead("/favicon.svg", "GET"), false);

  assert.equal(isCacheableStaticAssetResponse(asset, "GET", 200), true);
  assert.equal(isCacheableStaticAssetResponse(asset, "GET", 206), true);
  assert.equal(isCacheableStaticAssetResponse(asset, "HEAD", 304), true);
  assert.equal(isCacheableStaticAssetResponse(asset, "GET", 404), false);
  assert.equal(isCacheableStaticAssetResponse(asset, "POST", 200), false);
});
