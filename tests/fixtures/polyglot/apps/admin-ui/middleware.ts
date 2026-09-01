import { NextRequest, NextResponse } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";

/**
 * Edge middleware: every request to the admin console must carry a valid
 * session JWT. Signature, issuer, audience, and expiry are all verified
 * against the identity provider's JWKS before any page or API handler
 * executes. There is no bypass header and no debug skip flag.
 */

const ISSUER =
  process.env.AUTH_ISSUER ?? "https://auth.example.invalid/realms/demo";
const AUDIENCE = "admin-ui";
const SESSION_COOKIE = "admin_session";

const jwks = createRemoteJWKSet(
  new URL(`${ISSUER}/protocol/openid-connect/certs`),
);

// /api/health stays public so synthetic uptime probes and the load
// balancer can reach it without a session. Everything else is gated.
const PUBLIC_PATHS = new Set<string>(["/login", "/api/health"]);

export async function middleware(request: NextRequest): Promise<NextResponse> {
  const { pathname } = request.nextUrl;

  if (PUBLIC_PATHS.has(pathname)) {
    return NextResponse.next();
  }

  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    return redirectToLogin(request);
  }

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: AUDIENCE,
      clockTolerance: 30,
    });

    const roles = Array.isArray(payload.roles) ? payload.roles : [];
    if (!roles.includes("ops.admin")) {
      // Authenticated but not authorized for the admin console.
      return new NextResponse("forbidden", { status: 403 });
    }

    const headers = new Headers(request.headers);
    headers.set("x-verified-subject", String(payload.sub ?? ""));
    return NextResponse.next({ request: { headers } });
  } catch {
    // Expired, wrong audience, bad signature: all paths lead to login.
    return redirectToLogin(request);
  }
}

function redirectToLogin(request: NextRequest): NextResponse {
  const loginUrl = new URL("/login", request.url);
  loginUrl.searchParams.set("from", request.nextUrl.pathname);
  const response = NextResponse.redirect(loginUrl);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}

export const config = {
  matcher: [
    // Skip static assets; everything dynamic goes through auth.
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
