using AUTH_JWT.Options;
using AUTH_JWT.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AUTH_JWT.Authentication;

public sealed class JwtBearerOptionsSetup : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly JwtSigningKey _signingKey;
    private readonly JwtOptions _jwt;

    public JwtBearerOptionsSetup(JwtSigningKey signingKey, IOptions<JwtOptions> jwt)
    {
        _signingKey = signingKey;
        _jwt = jwt.Value;
    }

    public void Configure(JwtBearerOptions options) => Configure(JwtBearerDefaults.AuthenticationScheme, options);

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name is not null &&
            !string.Equals(name, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return;
        }

        options.RequireHttpsMetadata = true;
        options.SaveToken = false;
        options.IncludeErrorDetails = false;
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingKey.Key,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ValidTypes = [JwtOptions.AccessTokenType],
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = "role",
        };
        options.Events = new JwtBearerEvents
        {
            OnChallenge = WriteUnauthorized,
            OnForbidden = WriteForbidden,
        };
    }

    private static Task WriteUnauthorized(JwtBearerChallengeContext context)
    {
        context.HandleResponse();
        if (context.Response.HasStarted)
        {
            return Task.CompletedTask;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = context.AuthenticateFailure is null
            ? "Bearer"
            : "Bearer error=\"invalid_token\"";

        return Results.Problem(
            title: "Unauthorized",
            detail: "A valid bearer token is required.",
            statusCode: StatusCodes.Status401Unauthorized).ExecuteAsync(context.HttpContext);
    }

    private static Task WriteForbidden(ForbiddenContext context)
    {
        if (context.Response.HasStarted)
        {
            return Task.CompletedTask;
        }

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Results.Problem(
            title: "Forbidden",
            detail: "You do not have access to this resource.",
            statusCode: StatusCodes.Status403Forbidden).ExecuteAsync(context.HttpContext);
    }
}
