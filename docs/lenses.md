# The Four Reading Lenses

Every unit of code is read by four specialist lenses per pass, not by one
generalist. Independent readers have different blind spots, so the pooled
result is stronger than any one reader's result. The lenses make those
differences deliberate.
Each reader lane reads every file in its unit but hunts its lens's list
first and deepest.

A unit-and-lens pair forms a review lane. Lanes run as independent,
parallel agent contexts with no shared state, and passes repeat until the
unit goes quiet (two consecutive passes with almost nothing new).

## L1 - Authentication and Authorization

Missing or disabled authentication on endpoints, controllers, filters, and
gateways; authorization checks that are absent, inverted, or trust
client-supplied identity (IDs, roles, headers, tokens taken from the
request); missing ownership and tenant binding; session and token
lifecycle (issuance, validation, audience, expiry, revocation); MFA and
step-up bypass; admin and actuator surfaces; impersonation flows; API
gateway authorizers and their failure modes, especially fail-open.

## L2 - Secrets, Cryptography, and Key Material

Committed credentials, tokens, keys, and keystores (including whether
committed material decrypts other committed material); hardcoded or
default encryption keys; weak or misused cryptography (ECB mode, static
IVs, non-constant-time comparisons, MD5/SHA1 for authentication, homegrown
crypto); key derivation and storage; vault/KMS/HSM integration and its
fallbacks; secrets in build files, container definitions, and test
fixtures; certificate and TLS validation (hostname verification,
trust-all managers).

## L3 - Injection and Data Flow

This lens works sink-first: it starts from dangerous operations (process
spawns, deserializers, SQL assembly, file writes, queue publishers) and
traces backward to determine whether attacker-controlled input can reach
them. Findings cite the reach chain, not just the sink. Targets include
SQL/NoSQL/LDAP/command/expression injection, deserialization of untrusted
data, path traversal, server-side request forgery, template injection,
XXE and parser configuration, and log sinks.

## L4 - Infrastructure, Configuration, and Supply Chain

Open security groups and network paths; APIs without appropriate
authorization; wildcard IAM permissions; privileged containers; CI/CD
execution of untrusted input; unpinned dependencies and images; build and
deployment trust boundaries.

## Beyond the lenses

Two mechanisms extend the focused lanes:

- A **deterministic detector battery** runs over every unit before reading:
  regex-grade checks for high-confidence idioms (disabled TLS verification,
  static IVs, permissive CORS, and similar) that seed the reader briefs so
  model attention is spent on judgment, not pattern matching. Every battery
  hit is court-routed like any other candidate.
- **Cross-repo sweeps** dispatch after the first full pass: four bounded
  pattern-chasers, one per lens, that chase each lens's patterns across
  repository boundaries that unit partitioning may have split. Serious
  sweep findings re-enter the quiet law like any other discovery.

For how findings are verified and the run certified, see
[certification.md](certification.md).
