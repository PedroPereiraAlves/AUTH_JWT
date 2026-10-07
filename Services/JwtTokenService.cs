using System.Security.Claims;
using System.Text;
using AUTH_JWT.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AUTH_JWT.Services;

public sealed class JwtSigningKey
{
    public JwtSigningKey(IOptions<JwtOptions> options)
    {
        var key = options.Value.Key;
        var bytes = Encoding.UTF8.GetBytes(key);
        if (bytes.Length < JwtOptions.MinKeyBytes)
        {
            throw new InvalidOperationException("Jwt:Key is missing or shorter than 32 UTF-8 bytes.");
        }

        Key = new SymmetricSecurityKey(bytes);
    }

    public SymmetricSecurityKey Key { get; }
}

public sealed record IssuedAccessToken(string Token, DateTimeOffset ExpiresAtUtc);

public sealed class JwtTokenService
{
    private readonly JwtOptions _options;
    private readonly SigningCredentials _credentials;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtTokenService(IOptions<JwtOptions> options, JwtSigningKey signingKey)
    {
        _options = options.Value;
        _credentials = new SigningCredentials(signingKey.Key, SecurityAlgorithms.HmacSha256);
    }

    public IssuedAccessToken CreateAccessToken(string username)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(_options.ExpiresInMinutes);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            TokenType = JwtOptions.AccessTokenType,
            SigningCredentials = _credentials,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("D")),
                new Claim("client_id", _options.ClientId),
            ]),
        };

        return new IssuedAccessToken(_handler.CreateToken(descriptor), new DateTimeOffset(expires, TimeSpan.Zero));
    }
}
