// notify-svc: notification dispatch microservice (fixture estate).
// Module path uses example.invalid on purpose; this module is never
// fetched, built, or published. Versions are pinned so scanner test
// snapshots stay stable.
module example.invalid/demo/notify-svc

go 1.25.0

require (
	// Bearer-token verification (RS256, issuer + audience enforced).
	github.com/golang-jwt/jwt/v5 v5.2.2
	// Random notification ids (UUIDv4).
	github.com/google/uuid v1.6.0
	// PostgreSQL driver/pool; all queries are parameterized ($1, $2...).
	github.com/jackc/pgx/v5 v5.9.2
)

// Transitive dependencies of pgx; listed explicitly so dependency
// audits in CI see the full closure without network access.
require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

// Replace directives are forbidden in this repo; the scanner's
// supply-chain reader asserts none are present in the baseline.
