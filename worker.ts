import vinextHandler from "vinext/server/fetch-handler";
import {
  IMMUTABLE_ASSET_CACHE,
  isCacheableStaticAssetResponse,
  isStaticAssetRead,
  SECURITY_HEADERS,
} from "@/lib/security-headers";

interface WorkerEnv extends Cloudflare.Env {
  ASSETS?: Fetcher;
}

export default {
  async fetch(request, env, context) {
    const pathname = new URL(request.url).pathname;
    const isAssetRead = isStaticAssetRead(pathname, request.method);
    const response =
      isAssetRead && env.ASSETS
        ? await env.ASSETS.fetch(request)
        : await vinextHandler.fetch(request, env, context);
    const headers = new Headers(response.headers);

    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      headers.set(name, value);
    }

    if (
      isCacheableStaticAssetResponse(
        pathname,
        request.method,
        response.status,
      )
    ) {
      headers.set("Cache-Control", IMMUTABLE_ASSET_CACHE);
    } else if (isAssetRead) {
      headers.set("Cache-Control", "no-store");
    }

    return new Response(response.body, {
      headers,
      status: response.status,
      statusText: response.statusText,
    });
  },
} satisfies ExportedHandler<WorkerEnv>;
