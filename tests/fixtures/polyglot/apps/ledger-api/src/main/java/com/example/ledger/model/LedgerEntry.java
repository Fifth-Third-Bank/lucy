package com.example.ledger.model;

import java.time.Instant;
import java.util.UUID;

/**
 * One immutable row in the double-entry ledger.
 *
 * <p>Amounts are stored in integer cents to avoid floating point drift.
 * A transfer always produces two rows (a debit and a credit) inside a
 * single database transaction, so the per-tenant sum is invariant.
 *
 * <p>This record is part of the fixture estate: it is intentionally
 * boring so scanner e2e assertions about the surrounding files stay
 * stable across releases.
 */
public record LedgerEntry(
        UUID id,
        UUID accountId,
        UUID tenantId,
        long amountCents,
        String currency,
        String memo,
        Instant postedAt) {

    /** Debits are negative by convention. */
    public boolean isDebit() {
        return amountCents < 0;
    }

    /** Credits are positive by convention. */
    public boolean isCredit() {
        return amountCents > 0;
    }
}
