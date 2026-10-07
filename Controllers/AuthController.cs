using System.Security.Cryptography;
using System.Text;
using AUTH_JWT.Models;
using AUTH_JWT.Options;
using AUTH_JWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AUTH_JWT.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly DemoAuthOptions _demoAuth;
    private readonly JwtTokenService _tokens;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IOptions<DemoAuthOptions> demoAuth,
        JwtTokenService tokens,
        ILogger<AuthController> logger)
    {
        _demoAuth = demoAuth.Value;
        _tokens = tokens;
        _logger = logger;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType<LoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Login([FromBody] LoginModel login)
    {
        var usernameMatches = SecretsMatch(_demoAuth.Username, login.Username);
        var passwordMatches = SecretsMatch(_demoAuth.Password, login.Password);
        if (!(usernameMatches & passwordMatches))
        {
            _logger.LogWarning("Login failed for user {Username}", login.Username);
            Response.Headers.WWWAuthenticate = "Bearer";
            return Problem(
                title: "Invalid credentials",
                detail: "The username or password is incorrect.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var issued = _tokens.CreateAccessToken(login.Username);
        _logger.LogInformation("Login succeeded for user {Username}", login.Username);
        return Ok(new LoginResponse(issued.Token, "Bearer", issued.ExpiresAtUtc));
    }

    // Hash both sides so different lengths still compare in constant time.
    private static bool SecretsMatch(string expected, string provided)
    {
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(provided));
        return CryptographicOperations.FixedTimeEquals(expectedHash, providedHash);
    }
}
