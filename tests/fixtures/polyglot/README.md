# Polyglot Fixture Estate

A synthetic, miniature multi-repo estate that imitates a multi-service
application. It exists solely as a test fixture for the LUCY scanner: the
canary planter mutates these files during unit/e2e runs, and the readers
verify what was (and was not) changed.

**Nothing here is deployable.** The code is compile-plausible but has no
build artifacts, no real endpoints (all hosts use `example.invalid`), and
no credentials of any kind. Do not add real secrets, hostnames, or
personal data to this tree.

## Layout

| Path                  | Stack                  | What it imitates                          |
| --------------------- | ---------------------- | ----------------------------------------- |
| `apps/ledger-api`     | Java / Spring Boot     | Tenant-scoped record service              |
| `apps/portal-bff`     | C# / ASP.NET Core      | Customer portal backend-for-frontend      |
| `apps/admin-ui`       | TypeScript / Next.js   | Internal ops/admin console                |
| `apps/batch-worker`   | Ruby / Sinatra         | Background batch intake                   |
| `apps/notify-svc`     | Go / net/http          | Notification dispatch microservice        |
| `shared/crypto-lib`   | Python                 | Shared AEAD envelope-encryption library   |
| `infra`               | Terraform (HCL)        | ALB, API Gateway, and IAM definitions     |
| `deploy`              | YAML / Dockerfile      | Kubernetes manifest, image build, CI      |

## Baseline invariants (tests depend on these)

1. Every file is SECURE by default. Auth checks present, SQL is
   parameterized, JWT issuer/audience/signature validation is on,
   IAM policies are scoped, containers run non-root, ingress is
   443-only. The planter INTRODUCES weaknesses; the baseline has none.
2. Every file parses in its native toolchain. No placeholder syntax.
3. The words "synthetic", "test", and "scanner" already occur in
   legitimate identifiers and comments in several baseline files
   (for example `SyntheticAccountService.java`, `test_aead.py`, and
   the image-scanner stage of `.ci/pipeline.yml`). Marker validation
   in the planter must not false-positive on those pre-existing,
   benign occurrences.

## Regenerating

This tree is hand-maintained. If you change a file, keep it under
120 lines, keep it secure-by-default, and keep it syntactically valid,
then update the e2e snapshot fixtures that reference it.

Maintainer: dev@example.invalid
