using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PortalBff.Models;
using PortalBff.Services;

namespace PortalBff.Controllers;

/// <summary>
/// Portfolio views for the customer portal. The tenant segment in the
/// route is treated as UNTRUSTED input: it must match the tenant claim
/// in the verified bearer token or the request is refused before any
/// upstream call is made.
/// </summary>
[ApiController]
[Route("api/v1/tenants/{tenantId:guid}/portfolios")]
public sealed class PortfolioController : ControllerBase
{
    private const string TenantClaim = "tenant_id";

    private readonly IPortfolioReader _portfolios;
    private readonly ILogger<PortfolioController> _logger;

    public PortfolioController(
        IPortfolioReader portfolios,
        ILogger<PortfolioController> logger)
    {
        _portfolios = portfolios;
        _logger = logger;
    }

    [HttpGet]
    [Authorize(Policy = "PortfolioRead")]
    public async Task<ActionResult<IReadOnlyList<PortfolioSummary>>> List(
        Guid tenantId, CancellationToken ct)
    {
        if (!CallerBelongsTo(tenantId))
        {
            _logger.LogWarning("Cross-tenant portfolio list refused");
            return Forbid();
        }

        var summaries = await _portfolios.ListAsync(tenantId, ct);
        return Ok(summaries);
    }

    [HttpGet("{portfolioId:guid}")]
    [Authorize(Policy = "PortfolioRead")]
    public async Task<ActionResult<PortfolioDetail>> Get(
        Guid tenantId, Guid portfolioId, CancellationToken ct)
    {
        if (!CallerBelongsTo(tenantId))
        {
            return Forbid();
        }

        var detail = await _portfolios.GetAsync(tenantId, portfolioId, ct);
        return detail is null ? NotFound() : Ok(detail);
    }

    /// <summary>
    /// The tenant binding always comes from the validated token, never
    /// from headers or the route alone.
    /// </summary>
    private bool CallerBelongsTo(Guid tenantId)
    {
        var claim = User.FindFirst(TenantClaim)?.Value;
        return Guid.TryParse(claim, out var callerTenant)
            && callerTenant == tenantId;
    }
}
