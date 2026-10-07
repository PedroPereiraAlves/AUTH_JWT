# AUTH_JWT

Small ASP.NET Core API that signs and validates its own HS256 access tokens. It is a closed demo, not a production identity provider. Production apps should issue tokens from an OpenID Connect or OAuth authorization server and validate that server's asymmetric keys.

## Configure the signing key

`Jwt:Key` is required and is left blank in source. HS256 needs a UTF-8 key of at least 32 bytes. Set it with user secrets (Development) or the environment (any environment):

```bash
dotnet user-secrets set "Jwt:Key" "replace-with-a-local-dev-key-32b-min"
```

```bash
export Jwt__Key="replace-with-a-local-dev-key-32b-min"
```

The process exits on startup if the key is missing, shorter than 32 bytes, or longer than 512 bytes. Issuer, audience, client id, and lifetime are in `appsettings.json` (`Jwt` section). Access tokens expire after `Jwt:ExpiresInMinutes` (1–60, default 30).

## Run

Requires the .NET 10 SDK.

```bash
dotnet run --launch-profile Auth_JWT
```

The launch profile listens on `https://localhost:7008` and `http://localhost:5164`. Override with `ASPNETCORE_URLS` when you need different addresses.

Demo login (sample only, no user store): username `test`, password `password`. Override with `DemoAuth:Username` and `DemoAuth:Password`.

## Endpoints

`POST /api/auth/login` with JSON `{"username":"test","password":"password"}`.

Success returns `token`, `tokenType` (`Bearer`), and `expiresAtUtc`. Send the token as `Authorization: Bearer <token>`.

`GET /api/values` requires a valid token. `GET /api/values/public` does not.

Validation requires the configured issuer, audience, HS256 signature, `typ` of `at+jwt`, and expiration. Clock skew is 30 seconds. Failures use `application/problem+json`. A 401 includes a `WWW-Authenticate: Bearer` challenge. The response does not say whether the username or the password was wrong, and it does not include token-validation diagnostics.
