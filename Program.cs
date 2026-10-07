using AUTH_JWT.Authentication;
using AUTH_JWT.Options;
using AUTH_JWT.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace AUTH_JWT;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
        });

        builder.Services.AddControllers();
        builder.Services.AddProblemDetails();
        builder.Services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidator>();
        builder.Services.AddSingleton<IValidateOptions<DemoAuthOptions>, DemoAuthOptionsValidator>();
        builder.Services.AddOptions<JwtOptions>()
            .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
            .ValidateOnStart();
        builder.Services.AddOptions<DemoAuthOptions>()
            .Bind(builder.Configuration.GetSection(DemoAuthOptions.SectionName))
            .ValidateOnStart();
        builder.Services.AddSingleton<JwtSigningKey>();
        builder.Services.AddSingleton<JwtTokenService>();
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();
        builder.Services.AddSingleton<IConfigureOptions<JwtBearerOptions>, JwtBearerOptionsSetup>();
        builder.Services.AddAuthorization();

        var app = builder.Build();

        app.UseExceptionHandler(handler =>
        {
            handler.Run(async context =>
            {
                var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
                var environment = context.RequestServices.GetRequiredService<IHostEnvironment>();
                var status = exception is BadHttpRequestException bad
                    ? bad.StatusCode
                    : StatusCodes.Status500InternalServerError;

                await Results.Problem(
                    title: "An unexpected error occurred.",
                    detail: environment.IsDevelopment() ? exception?.Message : null,
                    statusCode: status).ExecuteAsync(context);
            });
        });
        app.UseStatusCodePages(async statusContext =>
        {
            var response = statusContext.HttpContext.Response;
            if (response.HasStarted)
            {
                return;
            }

            var status = response.StatusCode;
            await Results.Problem(
                title: ReasonPhrases.GetReasonPhrase(status),
                statusCode: status).ExecuteAsync(statusContext.HttpContext);
        });

        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();
        app.Run();
    }
}
