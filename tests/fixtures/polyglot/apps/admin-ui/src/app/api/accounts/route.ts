import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { assertRole, requireSession, UnauthorizedError } from "@/lib/auth";

/**
 * GET /api/accounts — proxied, tenant-scoped account listing for the
 * admin console. The handler re-verifies the session (defense in depth
 * on top of middleware), enforces the ops.admin role, validates query
 * input with zod, and only then calls the upstream ledger API using the
 * caller's tenant from the VERIFIED token — never from the query string.
 */

const LEDGER_API_BASE =
  process.env.LEDGER_API_BASE ?? "https://ledger-api.internal.example.invalid";

const querySchema = z.object({
  status: z.enum(["active", "frozen", "closed"]).default("active"),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().regex(/^[A-Za-z0-9_-]{0,64}$/).optional(),
});

export async function GET(request: NextRequest): Promise<NextResponse> {
  let session;
  try {
    session = await requireSession();
    assertRole(session, "ops.admin");
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
    throw error;
  }

  const parsed = querySchema.safeParse(
    Object.fromEntries(request.nextUrl.searchParams),
  );
  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid query", issues: parsed.error.issues },
      { status: 400 },
    );
  }

  const upstream = new URL(
    `/internal/v1/tenants/${encodeURIComponent(session.tenantId)}/accounts`,
    LEDGER_API_BASE,
  );
  upstream.searchParams.set("status", parsed.data.status);
  upstream.searchParams.set("limit", String(parsed.data.limit));
  if (parsed.data.cursor) {
    upstream.searchParams.set("cursor", parsed.data.cursor);
  }

  const response = await fetch(upstream, {
    headers: {
      // Delegated identity: the upstream re-checks scope and tenant.
      authorization: request.headers.get("authorization") ?? "",
      accept: "application/json",
    },
    cache: "no-store",
  });

  if (!response.ok) {
    return NextResponse.json({ error: "upstream error" }, { status: 502 });
  }

  const body: unknown = await response.json();
  return NextResponse.json(body, { status: 200 });
}
