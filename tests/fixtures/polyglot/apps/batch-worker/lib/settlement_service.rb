# frozen_string_literal: true

require "pg"
require "securerandom"

# Persistence for scheduled jobs in the synthetic fixture. Source tags let
# tests exercise tenant-scoped reconciliation across multiple input paths.
#
# All SQL goes through exec_params. Interpolating values into SQL text
# is a build-breaking review violation in this repo.
class SettlementService
  SCANNER_SOURCE = "demo_batch_source"

  INSERT_JOB_SQL = <<~SQL
    INSERT INTO settlement_jobs (id, tenant_id, batch_date, source, requested_by, state, created_at)
    VALUES ($1, $2, $3, $4, $5, 'queued', now())
  SQL

  FIND_JOB_SQL = <<~SQL
    SELECT id, tenant_id, batch_date, source, requested_by, state, created_at
      FROM settlement_jobs
     WHERE id = $1 AND tenant_id = $2
  SQL

  COUNT_SCANNER_ITEMS_SQL = <<~SQL
    SELECT COUNT(*) AS n
      FROM check_items
     WHERE tenant_id = $1 AND batch_date = $2 AND source = $3
  SQL

  def initialize(connection: nil)
    @conn = connection || PG.connect(
      host: ENV.fetch("PGHOST", "settlement-db.internal.example.invalid"),
      dbname: ENV.fetch("PGDATABASE", "settlement"),
      user: ENV.fetch("PGUSER"),
      password: ENV.fetch("PGPASSWORD"),
      sslmode: "verify-full"
    )
  end

  def enqueue_settlement(tenant_id:, batch_date:, requested_by:)
    job_id = SecureRandom.uuid
    @conn.exec_params(
      INSERT_JOB_SQL,
      [job_id, tenant_id, batch_date, SCANNER_SOURCE, requested_by]
    )
    job_id
  end

  # Tenant id always accompanies the primary key so one tenant can never
  # read another tenant's job by guessing UUIDs.
  def find_job(job_id:, tenant_id:)
    result = @conn.exec_params(FIND_JOB_SQL, [job_id, tenant_id])
    return nil if result.ntuples.zero?

    row = result[0]
    {
      "job_id" => row["id"],
      "batch_date" => row["batch_date"],
      "source" => row["source"],
      "state" => row["state"],
      "created_at" => row["created_at"]
    }
  end

  def scanner_item_count(tenant_id:, batch_date:)
    result = @conn.exec_params(
      COUNT_SCANNER_ITEMS_SQL,
      [tenant_id, batch_date, SCANNER_SOURCE]
    )
    result[0]["n"].to_i
  end
end
