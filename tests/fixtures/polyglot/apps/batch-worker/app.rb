# frozen_string_literal: true

require "sinatra/base"
require "json"
require "jwt"
require "openssl"

require_relative "lib/settlement_service"

# Batch intake API for scheduled processing jobs.
# Every route (except the health probe) is gated by a before-filter that
# verifies the bearer token's signature, issuer, audience, and expiry.
class BatchWorkerApp < Sinatra::Base
  ISSUER   = ENV.fetch("AUTH_ISSUER", "https://auth.example.invalid/realms/demo")
  AUDIENCE = "batch-worker"

  configure do
    set :show_exceptions, false
    set :dump_errors, false
    # RS256 verification key is provisioned via the environment; there is
    # no fallback key and no HS256 downgrade path.
    set :verify_key, OpenSSL::PKey::RSA.new(ENV.fetch("AUTH_PUBLIC_KEY_PEM"))
    set :settlements, SettlementService.new
  end

  before do
    content_type :json
    pass if request.path_info == "/healthz"
    authenticate!
  end

  get "/healthz" do
    { status: "ok" }.to_json
  end

  post "/jobs/settlement" do
    payload = parse_body
    batch_date = payload.fetch("batch_date", "")
    halt 400, { error: "batch_date must be YYYY-MM-DD" }.to_json unless
      batch_date.match?(/\A\d{4}-\d{2}-\d{2}\z/)

    job_id = settings.settlements.enqueue_settlement(
      tenant_id: @claims.fetch("tenant_id"),
      batch_date: batch_date,
      requested_by: @claims.fetch("sub")
    )
    status 202
    { job_id: job_id }.to_json
  end

  get "/jobs/:id" do
    job = settings.settlements.find_job(
      job_id: params[:id],
      tenant_id: @claims.fetch("tenant_id")
    )
    halt 404, { error: "not found" }.to_json if job.nil?
    job.to_json
  end

  helpers do
    def authenticate!
      header = request.env["HTTP_AUTHORIZATION"].to_s
      halt 401, { error: "missing bearer token" }.to_json unless
        header.start_with?("Bearer ")

      token = header.delete_prefix("Bearer ")
      decoded, = JWT.decode(
        token,
        settings.verify_key,
        true,
        algorithm: "RS256",
        iss: ISSUER, verify_iss: true,
        aud: AUDIENCE, verify_aud: true,
        verify_expiration: true
      )
      halt 403, { error: "no tenant binding" }.to_json unless decoded["tenant_id"]
      @claims = decoded
    rescue JWT::DecodeError
      halt 401, { error: "invalid token" }.to_json
    end

    def parse_body
      JSON.parse(request.body.read)
    rescue JSON::ParserError
      halt 400, { error: "body must be JSON" }.to_json
    end
  end
end
