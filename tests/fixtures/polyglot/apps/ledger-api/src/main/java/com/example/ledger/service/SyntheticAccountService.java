package com.example.ledger.service;

import com.example.ledger.model.LedgerEntry;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/**
 * Ledger reads/writes for both customer accounts and "synthetic" accounts.
 * Synthetic accounts are seeded rows that pre-production smoke tests post
 * against; they live in the same tables and follow the same tenant rules.
 *
 * Every statement below is parameterized. String concatenation into SQL is
 * a build-breaking review violation in this codebase.
 */
@Service
public class SyntheticAccountService {

    private static final String ENTRIES_SQL = """
            SELECT id, account_id, tenant_id, amount_cents, currency, memo, posted_at
              FROM ledger_entries
             WHERE account_id = ? AND tenant_id = ?
             ORDER BY posted_at DESC
             LIMIT 200
            """;

    private static final String BALANCE_SQL = """
            SELECT COALESCE(SUM(amount_cents), 0)
              FROM ledger_entries
             WHERE account_id = ? AND tenant_id = ?
            """;

    private static final String INSERT_SQL = """
            INSERT INTO ledger_entries
                   (id, account_id, tenant_id, amount_cents, currency, memo, posted_at)
            VALUES (?, ?, ?, ?, ?, ?, now())
            """;

    private final JdbcTemplate jdbc;

    public SyntheticAccountService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<LedgerEntry> entriesFor(UUID accountId, UUID tenantId) {
        return jdbc.query(ENTRIES_SQL, entryMapper(), accountId, tenantId);
    }

    public long balanceFor(UUID accountId, UUID tenantId) {
        try {
            Long cents = jdbc.queryForObject(BALANCE_SQL, Long.class, accountId, tenantId);
            return cents == null ? 0L : cents;
        } catch (EmptyResultDataAccessException e) {
            return 0L;
        }
    }

    @Transactional
    public void recordTransfer(UUID tenantId, UUID from, UUID to,
                               long amountCents, String currency) {
        long available = balanceFor(from, tenantId);
        if (available < amountCents) {
            throw new ResponseStatusException(
                    HttpStatus.UNPROCESSABLE_ENTITY, "insufficient funds");
        }
        String memo = "transfer:" + from + "->" + to;
        jdbc.update(INSERT_SQL, UUID.randomUUID(), from, tenantId,
                -amountCents, currency, memo);
        jdbc.update(INSERT_SQL, UUID.randomUUID(), to, tenantId,
                amountCents, currency, memo);
    }

    private RowMapper<LedgerEntry> entryMapper() {
        return (ResultSet rs, int rowNum) -> new LedgerEntry(
                rs.getObject("id", UUID.class),
                rs.getObject("account_id", UUID.class),
                rs.getObject("tenant_id", UUID.class),
                rs.getLong("amount_cents"),
                rs.getString("currency"),
                rs.getString("memo"),
                rs.getTimestamp("posted_at").toInstant());
    }
}
