using System.Text;
using Microsoft.Extensions.Options;

namespace AUTH_JWT.Options;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public const string AccessTokenType = "at+jwt";

    public const int MinKeyBytes = 32;

    public const int MaxKeyBytes = 512;

    public string Key { get; set; } = "";

    public string Issuer { get; set; } = "";

    public string Audience { get; set; } = "";

    public string ClientId { get; set; } = "";

    public int ExpiresInMinutes { get; set; } = 30;
}

public sealed class JwtOptionsValidator : IValidateOptions<JwtOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add("Jwt:Issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add("Jwt:Audience is required.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            failures.Add("Jwt:ClientId is required.");
        }

        if (options.ExpiresInMinutes is < 1 or > 60)
        {
            failures.Add("Jwt:ExpiresInMinutes must be between 1 and 60.");
        }

        if (string.IsNullOrWhiteSpace(options.Key))
        {
            failures.Add(
                "Jwt:Key is required. Set the Jwt__Key environment variable or run: dotnet user-secrets set \"Jwt:Key\" \"<32-byte-or-longer-dev-key>\".");
        }
        else
        {
            var keyBytes = Encoding.UTF8.GetByteCount(options.Key);
            if (keyBytes < JwtOptions.MinKeyBytes || keyBytes > JwtOptions.MaxKeyBytes)
            {
                failures.Add(
                    $"Jwt:Key must be {JwtOptions.MinKeyBytes}-{JwtOptions.MaxKeyBytes} UTF-8 bytes so HS256 meets the HMAC key-size requirement. Do not commit the key.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
