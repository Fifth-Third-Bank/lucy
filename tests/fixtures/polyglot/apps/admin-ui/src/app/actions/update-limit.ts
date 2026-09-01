"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { assertRole, requireSession } from "@/lib/auth";

/**
 * Server action: update the daily transfer limit on an account.
 *
 * Server actions are directly invokable endpoints, so this file performs
 * its own session verification and role check; it never trusts the form
 * to have been rendered behind middleware.
 */

const LEDGER_API_BASE =
  process.env.LEDGER_API_BASE ?? "https://ledger-api.internal.example.invalid";

const updateLimitSchema = z.object({
  accountId: z.string().uuid(),
  dailyLimitCents: z.coerce
    .number()
    .int()
    .min(0)
    .max(10_000_000_00), // bounded synthetic-fixture value
  reason: z.string().min(10).max(500),
});

export interface UpdateLimitResult {
  ok: boolean;
  message: string;
}

export async function updateDailyLimit(
  formData: FormData,
): Promise<UpdateLimitResult> {
  // 1. Authentication + authorization, from the verified token only.
  const session = await requireSession();
  assertRole(session, "ops.admin");

  // 2. Input validation before anything touches the upstream API.
  const parsed = updateLimitSchema.safeParse({
    accountId: formData.get("accountId"),
    dailyLimitCents: formData.get("dailyLimitCents"),
    reason: formData.get("reason"),
  });
  if (!parsed.success) {
    return { ok: false, message: "invalid input" };
  }

  // 3. Tenant comes from the session, so an admin of tenant A can never
  //    address an account under tenant B regardless of form contents.
  const upstream = new URL(
    `/internal/v1/tenants/${encodeURIComponent(session.tenantId)}` +
      `/accounts/${encodeURIComponent(parsed.data.accountId)}/limits`,
    LEDGER_API_BASE,
  );

  const response = await fetch(upstream, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      dailyLimitCents: parsed.data.dailyLimitCents,
      reason: parsed.data.reason,
      changedBy: session.subject,
    }),
    cache: "no-store",
  });

  if (!response.ok) {
    return { ok: false, message: "limit update rejected upstream" };
  }

  revalidatePath("/accounts");
  return { ok: true, message: "daily limit updated" };
}
