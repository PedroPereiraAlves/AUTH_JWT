namespace AUTH_JWT.Models;

public sealed record LoginResponse(string Token, string TokenType, DateTimeOffset ExpiresAtUtc);
