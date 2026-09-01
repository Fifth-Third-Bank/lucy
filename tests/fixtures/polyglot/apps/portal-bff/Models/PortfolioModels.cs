namespace PortalBff.Models;

/// <summary>
/// Lightweight projection of a portfolio for list views. Values are
/// integer cents; the UI layer owns formatting and localization.
/// </summary>
public sealed record PortfolioSummary(
    Guid PortfolioId,
    Guid TenantId,
    string DisplayName,
    long MarketValueCents,
    string Currency,
    DateTimeOffset AsOf);

/// <summary>
/// Full portfolio view including positions. Returned only after the
/// controller has confirmed the caller's tenant binding.
/// </summary>
public sealed record PortfolioDetail(
    Guid PortfolioId,
    Guid TenantId,
    string DisplayName,
    long MarketValueCents,
    long CostBasisCents,
    string Currency,
    DateTimeOffset AsOf,
    IReadOnlyList<Position> Positions);

/// <summary>
/// One holding inside a portfolio. Quantity is scaled by 10^8 so that
/// fractional shares survive integer arithmetic.
/// </summary>
public sealed record Position(
    string Symbol,
    long QuantityE8,
    long MarketValueCents,
    long CostBasisCents);

/// <summary>
/// Error envelope shared by the portal BFF endpoints. Detail strings are
/// generic on purpose; internal diagnostics stay in structured logs.
/// </summary>
public sealed record ApiError(
    string Code,
    string Message,
    string TraceId);
