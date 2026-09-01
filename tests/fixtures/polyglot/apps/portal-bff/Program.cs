using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using PortalBff.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// ---------------------------------------------------------------------------
// Authentication: every token must come from the demo realm and be
// scoped to this audience. Issuer, audience, lifetime, and signing key
// validation are ALL enabled; signing keys are pulled from the authority's
// OIDC metadata over HTTPS (RequireHttpsMetadata stays true).
// ---------------------------------------------------------------------------
var authority = builder.Configuration["Jwt:Authority"]
    ?? throw new InvalidOperationException("Jwt:Authority is required");
var audience = builder.Configuration["Jwt:Audience"]
    ?? throw new InvalidOperationException("Jwt:Audience is required");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = audience;
        options.RequireHttpsMetadata = true;
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = authority,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    });

// Deny-by-default: any endpoint without an explicit [Authorize] policy
// still requires an authenticated principal via the fallback policy.
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("PortfolioRead", policy =>
        policy.RequireAuthenticatedUser().RequireClaim("scope", "portfolio:read"));
    options.AddPolicy("PortfolioWrite", policy =>
        policy.RequireAuthenticatedUser().RequireClaim("scope", "portfolio:write"));
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization
        .AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// Needed by the gateway reader to forward the caller's delegated token.
builder.Services.AddHttpContextAccessor();

// Typed HttpClient for the upstream ledger API. Certificate validation is
// the framework default (ON); no handler ever overrides it in this repo.
builder.Services.AddHttpClient<IPortfolioReader, LedgerGatewayPortfolioReader>(client =>
{
    var baseUrl = builder.Configuration["LedgerApi:BaseUrl"]
        ?? throw new InvalidOperationException("LedgerApi:BaseUrl is required");
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromSeconds(5);
});

builder.Services.AddHealthChecks();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Health endpoint is intentionally anonymous for load balancer probes.
app.MapHealthChecks("/healthz").AllowAnonymous();
app.MapControllers();

app.Run();
