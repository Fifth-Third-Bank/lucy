package com.example.ledger.web;

import com.example.ledger.model.LedgerEntry;
import com.example.ledger.service.SyntheticAccountService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Ledger REST surface. Every route requires an OAuth2 bearer token; the
 * scope check happens here and the tenant scoping happens in the service
 * layer, so a caller can never read another tenant's ledger rows.
 */
@RestController
@RequestMapping("/api/v1/ledger")
public class LedgerController {

    private final SyntheticAccountService accounts;

    public LedgerController(SyntheticAccountService accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/{accountId}/entries")
    @PreAuthorize("hasAuthority('SCOPE_ledger:read')")
    public ResponseEntity<List<LedgerEntry>> entries(
            @PathVariable UUID accountId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID tenantId = tenantOf(jwt);
        return ResponseEntity.ok(accounts.entriesFor(accountId, tenantId));
    }

    @GetMapping("/{accountId}/balance")
    @PreAuthorize("hasAuthority('SCOPE_ledger:read')")
    public ResponseEntity<BalanceResponse> balance(
            @PathVariable UUID accountId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID tenantId = tenantOf(jwt);
        long cents = accounts.balanceFor(accountId, tenantId);
        return ResponseEntity.ok(new BalanceResponse(accountId, cents, "USD"));
    }

    @PostMapping("/transfer")
    @PreAuthorize("hasAuthority('SCOPE_ledger:write')")
    public ResponseEntity<Void> transfer(
            @Valid @RequestBody TransferRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        UUID tenantId = tenantOf(jwt);
        accounts.recordTransfer(
                tenantId,
                request.fromAccountId(),
                request.toAccountId(),
                request.amountCents(),
                request.currency());
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    /** Tenant is taken from the verified token, never from the request. */
    private static UUID tenantOf(Jwt jwt) {
        String claim = jwt.getClaimAsString("tenant_id");
        if (claim == null || claim.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "token has no tenant binding");
        }
        return UUID.fromString(claim);
    }

    public record TransferRequest(
            @NotNull UUID fromAccountId,
            @NotNull UUID toAccountId,
            @Positive long amountCents,
            @NotBlank String currency) {
    }

    public record BalanceResponse(UUID accountId, long balanceCents, String currency) {
    }
}
