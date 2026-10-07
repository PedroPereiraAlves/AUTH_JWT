using Microsoft.Extensions.Options;

namespace AUTH_JWT.Options;

public sealed class DemoAuthOptions
{
    public const string SectionName = "DemoAuth";

    public string Username { get; set; } = "";

    public string Password { get; set; } = "";
}

public sealed class DemoAuthOptionsValidator : IValidateOptions<DemoAuthOptions>
{
    public ValidateOptionsResult Validate(string? name, DemoAuthOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Username) || options.Username.Length > 128)
        {
            failures.Add("DemoAuth:Username is required and must be at most 128 characters.");
        }

        if (string.IsNullOrWhiteSpace(options.Password) || options.Password.Length > 256)
        {
            failures.Add("DemoAuth:Password is required and must be at most 256 characters.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
