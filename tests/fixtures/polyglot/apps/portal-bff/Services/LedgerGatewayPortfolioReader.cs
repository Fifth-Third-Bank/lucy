using System.Net.Http.Headers;
using PortalBff.Models;

namespace PortalBff.Services;

/// <summary>
/// Read-side gateway to the upstream ledger API.
/// </summary>
public interface IPortfolioReader
{
    Task<IReadOnlyList<PortfolioSummary>> ListAsync(Guid tenantId, CancellationToken ct);
    Task<PortfolioDetail?> GetAsync(Guid tenantId, Guid portfolioId, CancellationToken ct);
}

/// <summary>
/// Calls ledger-api over HTTPS with the caller's delegated token.
/// TLS certificate validation is the HttpClient default (enabled);
/// this repo never installs a permissive server certificate callback.
/// </summary>
public sealed class LedgerGatewayPortfolioReader : IPortfolioReader
{
    private readonly HttpClient _http;
    private readonly IHttpContextAccessor _contextAccessor;

    public LedgerGatewayPortfolioReader(
        HttpClient http,
        IHttpContextAccessor contextAccessor)
    {
        _http = http;
        _contextAccessor = contextAccessor;
    }

    public async Task<IReadOnlyList<PortfolioSummary>> ListAsync(
        Guid tenantId, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"internal/v1/tenants/{tenantId}/portfolios");
        AttachDelegatedToken(request);

        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content
            .ReadFromJsonAsync<List<PortfolioSummary>>(cancellationToken: ct);
        return payload ?? new List<PortfolioSummary>();
    }

    public async Task<PortfolioDetail?> GetAsync(
        Guid tenantId, Guid portfolioId, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"internal/v1/tenants/{tenantId}/portfolios/{portfolioId}");
        AttachDelegatedToken(request);

        using var response = await _http.SendAsync(request, ct);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
        response.EnsureSuccessStatusCode();

        return await response.Content
            .ReadFromJsonAsync<PortfolioDetail>(cancellationToken: ct);
    }

    /// <summary>
    /// On-behalf-of: the user's own verified bearer token is forwarded, so
    /// the upstream service re-applies its own tenant and scope checks.
    /// </summary>
    private void AttachDelegatedToken(HttpRequestMessage request)
    {
        var header = _contextAccessor.HttpContext?
            .Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer "))
        {
            throw new InvalidOperationException("missing delegated bearer token");
        }
        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", header["Bearer ".Length..]);
    }
}
