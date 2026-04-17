using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading.RateLimiting;

#region BUILDER
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages(options =>
{
    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());

    options.Conventions.AddPageApplicationModelConvention(
        "/Error",
        model => model.Filters.Add(new IgnoreAntiforgeryTokenAttribute())
    );
});

builder.Services.AddLocalization();

builder.Services.AddAuthentication("Cookies")
    .AddCookie(options =>
    {
        options.LoginPath = "/";
        options.Cookie.Name = "__Host-Auth";

        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.IsEssential = true;

        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    });


builder.Services.AddAntiforgery(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.HeaderName = "X-CSRF-TOKEN";
});


builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // GLOBAL LIMITER
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var path = context.Request.Path.ToString();

        return RateLimitPartition.GetFixedWindowLimiter($"{ip}:{path}", _ =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            });
    });

    // LOGIN LIMITER (FIXÉ)
    options.AddPolicy("login", context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        string user = "anonymous";

        var key = $"{ip}:login";

        return RateLimitPartition.GetFixedWindowLimiter(key, _ =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            });
    });
});

builder.Services.AddMemoryCache();

builder.Services.AddSingleton<LoginAttemptService>();


builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 10 * 1024;
    options.AddServerHeader = false;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
    options.Limits.Http2.MaxStreamsPerConnection = 100;
});

builder.Services.AddDataProtection()
    .SetApplicationName("AppName")
    .PersistKeysToFileSystem(new DirectoryInfo(@"./keys"))
    .ProtectKeysWithDpapi();
#endregion

#region APP
var app = builder.Build();

// ---------------- CULTURE ----------------
var supportedCultures = new[]
{
    "fr", "en", "de", "es"
}
.Select(x => new CultureInfo(x))
.ToList();

var localizationOptions = new RequestLocalizationOptions
{
    DefaultRequestCulture = new RequestCulture("fr"),
    SupportedCultures = supportedCultures,
    SupportedUICultures = supportedCultures
};

// ---------------- ERROR HANDLING + LOGGING ----------------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();

    builder.Logging.ClearProviders();
    builder.Logging.AddConsole();
}

// ---------------- SECURITY HEADERS ----------------
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;

    var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
    context.Items["CSPNonce"] = nonce;

    context.Response.Headers["X-CSP-Nonce"] = nonce;

    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()";
    headers["X-Permitted-Cross-Domain-Policies"] = "none";
    headers["Expect-CT"] = "max-age=86400, enforce";
    headers["Cross-Origin-Opener-Policy"] = "same-origin";
    headers["Cross-Origin-Resource-Policy"] = "same-origin";
    headers["Cache-Control"] = "no-store";
    headers["Strict-Transport-Security"] =
        "max-age=63072000; includeSubDomains; preload";

    headers["X-DNS-Prefetch-Control"] = "off";


    headers["Content-Security-Policy"] =
    "default-src 'self'; " +
    "base-uri 'self'; " +
    "object-src 'none'; " +
    "frame-ancestors 'none'; " +
    "form-action 'self'; " +
    "script-src 'self'; " +
    "style-src 'self'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self';";


    await next();
});
app.Use(async (context, next) =>
{
    context.Response.Headers["Cache-Control"] = "no-store";
    await next();
});
// ---------------- PIPELINE ----------------
app.UseHttpsRedirection();

app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        var ext = Path.GetExtension(ctx.File.Name);

        if (ext == ".html")
        {
            ctx.Context.Response.Headers["Cache-Control"] = "no-store";
        }
        else
        {
            ctx.Context.Response.Headers["Cache-Control"] =
                "public,max-age=31536000,immutable";
        }

        ctx.Context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    }
});

app.UseRouting();

app.UseRateLimiter();
app.UseRequestLocalization(localizationOptions);

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
#endregion
app.Run();