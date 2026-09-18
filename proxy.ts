import { NextResponse } from "next/server";
import { SECURITY_HEADERS } from "@/lib/security-headers";

export function proxy() {
  const response = NextResponse.next();

  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(name, value);
  }

  return response;
}

export const config = {
  matcher: "/:path*",
};
