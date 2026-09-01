import { cookies } from "next/headers";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/**
 * Server-side session verification shared by API routes and server
 * actions. Middleware already gates the request path, but defense in
 * depth requires each server entry point to re-verify the token itself:
 * server actions can be invoked outside the middleware matcher.
 */

const ISSUER =
  process.env.AUTH_ISSUER ?? "https://auth.example.invalid/realms/demo";
const AUDIENCE = "admin-ui";
const SESSION_COOKIE = "admin_session";

const jwks = createRemoteJWKSet(
  new URL(`${ISSUER}/protocol/openid-connect/certs`),
);

export interface AdminSession {
  subject: string;
  tenantId: string;
  roles: readonly string[];
}

export class UnauthorizedError extends Error {
  constructor(message = "unauthorized") {
    super(message);
    this.name = "UnauthorizedError";
  }
}

/**
 * Verifies the session cookie and returns the caller's identity.
 * Throws UnauthorizedError on any validation failure; callers convert
 * that into a 401/redirect as appropriate for their surface.
 */
export async function requireSession(): Promise<AdminSession> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) {
    throw new UnauthorizedError("missing session cookie");
  }

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: AUDIENCE,
      clockTolerance: 30,
    }));
  } catch {
    throw new UnauthorizedError("session token failed verification");
  }

  const tenantId = typeof payload.tenant_id === "string" ? payload.tenant_id : "";
  if (!payload.sub || !tenantId) {
    throw new UnauthorizedError("token missing required claims");
  }

  return {
    subject: payload.sub,
    tenantId,
    roles: Array.isArray(payload.roles) ? payload.roles.map(String) : [],
  };
}

/** Role check helper so authorization reads consistently at call sites. */
export function assertRole(session: AdminSession, role: string): void {
  if (!session.roles.includes(role)) {
    throw new UnauthorizedError(`missing role: ${role}`);
  }
}
