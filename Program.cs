using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using WebSiteKontrol.Auth;
using WebSiteKontrol.Monitoring;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<LdapOptions>(builder.Configuration.GetSection(LdapOptions.SectionName));
builder.Services.Configure<SuperUserOptions>(builder.Configuration.GetSection(SuperUserOptions.SectionName));
builder.Services.Configure<LoginSecurityOptions>(builder.Configuration.GetSection(LoginSecurityOptions.SectionName));
builder.Services.Configure<SiteMonitorOptions>(builder.Configuration.GetSection(SiteMonitorOptions.SectionName));
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection(SmtpOptions.SectionName));
builder.Services.AddSingleton<ILdapAuthService, LdapAuthService>();
builder.Services.AddSingleton<LoginAttemptTracker>();
builder.Services.AddSingleton<ManagedServerRegistry>();
builder.Services.AddSingleton<ManagedSiteRegistry>();
builder.Services.AddHttpClient("SiteMonitor");
builder.Services.AddHostedService<SiteMonitorBackgroundService>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Cookie.Name = "websitekontrol.auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
    });
builder.Services.AddAuthorization();
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(Path.Combine(app.Environment.ContentRootPath, "css")),
    RequestPath = "/css",
});

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(Path.Combine(app.Environment.ContentRootPath, "images")),
    RequestPath = "/images",
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", async (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("/");
    }

    var loginPagePath = Path.Combine(app.Environment.ContentRootPath, "login.html");
    if (!File.Exists(loginPagePath))
    {
        return Results.Problem("Giris sayfasi bulunamadi.");
    }

    var html = await File.ReadAllTextAsync(loginPagePath);
    var errorText = GetErrorText(context.Request.Query["error"]);
    var returnUrl = context.Request.Query["returnUrl"].ToString();
    if (string.IsNullOrWhiteSpace(returnUrl))
    {
        returnUrl = context.Request.Query["ReturnUrl"].ToString();
    }

    html = html.Replace("{{ERROR_MESSAGE}}", WebUtility.HtmlEncode(errorText), StringComparison.Ordinal);
    html = html.Replace("{{RETURN_URL}}", WebUtility.HtmlEncode(returnUrl), StringComparison.Ordinal);

    return Results.Content(html, "text/html; charset=utf-8");
});

app.MapPost("/login", async (HttpContext context, ILdapAuthService ldapAuthService, IOptionsMonitor<LoginSecurityOptions> loginSecurityOptions, LoginAttemptTracker loginAttemptTracker) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();
    var returnUrl = SanitizeReturnUrl(form["returnUrl"].ToString());
    var clientIp = GetClientIp(context);
    var security = loginSecurityOptions.CurrentValue;

    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "empty_fields");
        return Results.Redirect($"/login?error=empty&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    if (loginAttemptTracker.IsLocked(username, clientIp, out _))
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "locked");
        return Results.Redirect($"/login?error=locked&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    if (security.UseEmailLoginOnly && !LooksLikeEmail(username))
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "email_required");
        return Results.Redirect($"/login?error=emailonly&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    if (LooksLikeEmail(username) && !IsAllowedEmailDomain(username, security))
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "invalid_domain");
        return Results.Redirect($"/login?error=domain&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    if (!IsAllowedLoginEmail(username, security))
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "not_allowed");
        return Results.Redirect($"/login?error=notallowed&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    var authResult = await ldapAuthService.AuthenticateAsync(username, password, context.RequestAborted);
    if (!authResult.Success || authResult.User is null)
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "ldap_failed");
        return Results.Redirect($"/login?error=invalid&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    var resolvedEmail = authResult.User.Email?.Trim() ?? username;
    if (!IsAllowedLoginEmail(resolvedEmail, security))
    {
        loginAttemptTracker.RegisterFailure(username, clientIp, "resolved_email_not_allowed");
        return Results.Redirect($"/login?error=notallowed&returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, authResult.User.Username),
        new(ClaimTypes.Name, authResult.User.DisplayName),
    };

    if (!string.IsNullOrWhiteSpace(authResult.User.Email))
    {
        claims.Add(new Claim(ClaimTypes.Email, authResult.User.Email));
    }

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        principal,
        new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8),
        });

    loginAttemptTracker.RegisterSuccess(username, clientIp);
    return Results.Redirect(returnUrl);
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
}).RequireAuthorization();

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
}).RequireAuthorization();

app.MapGet("/api/me", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? "";
    var name = context.User.FindFirstValue(ClaimTypes.Name) ?? "";
    var isSuperUser = IsSuperUser(email, superUserOptions.CurrentValue);
    return Results.Json(new { email, name, isSuperUser });
}).RequireAuthorization();

app.MapGet("/api/managed-sites", (ManagedSiteRegistry siteRegistry) =>
{
    return Results.Json(siteRegistry.GetAll());
}).RequireAuthorization();

app.MapGet("/admin", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? "";
    if (!IsSuperUser(email, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    var pagePath = Path.Combine(app.Environment.ContentRootPath, "admin.html");
    if (!File.Exists(pagePath))
    {
        return Results.Problem("Yonetim sayfasi bulunamadi.");
    }

    return Results.File(pagePath, "text/html; charset=utf-8");
}).RequireAuthorization();

app.MapGet("/api/admin/servers", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, ManagedServerRegistry serverRegistry) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    return Results.Json(serverRegistry.GetAll());
}).RequireAuthorization();

app.MapPost("/api/admin/servers", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, ManagedServerRegistry serverRegistry, ManagedServerEntry input) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    if (string.IsNullOrWhiteSpace(input.Name) || string.IsNullOrWhiteSpace(input.IpAddress))
    {
        return Results.BadRequest(new { detail = "Sunucu adi ve IP zorunludur." });
    }

    var saved = serverRegistry.Upsert(input);
    return Results.Json(saved);
}).RequireAuthorization();

app.MapDelete("/api/admin/servers", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, ManagedServerRegistry serverRegistry, ManagedSiteRegistry siteRegistry, string id) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    if (string.IsNullOrWhiteSpace(id))
    {
        return Results.BadRequest(new { detail = "id zorunludur." });
    }

    var inUse = siteRegistry.GetAll().Any(x => string.Equals(x.ServerId, id, StringComparison.OrdinalIgnoreCase));
    if (inUse)
    {
        return Results.BadRequest(new { detail = "Bu sunucuya bagli web kayitlari var. Once web kayitlarini tasiyin veya silin." });
    }

    var removed = serverRegistry.RemoveById(id);
    if (!removed)
    {
        return Results.NotFound(new { detail = "Sunucu kaydi bulunamadi." });
    }

    return Results.Ok(new { removed = true });
}).RequireAuthorization();

app.MapGet("/api/admin/sites", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, ManagedSiteRegistry siteRegistry) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    return Results.Json(siteRegistry.GetAll());
}).RequireAuthorization();

app.MapPost("/api/admin/sites", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, ManagedSiteRegistry siteRegistry, ManagedSiteEntry input) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    if (string.IsNullOrWhiteSpace(input.Url) || string.IsNullOrWhiteSpace(input.UnitName))
    {
        return Results.BadRequest(new { detail = "URL ve Birim adi zorunludur." });
    }

    try
    {
        var saved = siteRegistry.Upsert(input);
        return Results.Json(saved);
    }
    catch
    {
        return Results.BadRequest(new { detail = "Gecersiz URL formati." });
    }
}).RequireAuthorization();

app.MapDelete("/api/admin/sites", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, ManagedSiteRegistry siteRegistry, string id) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    if (string.IsNullOrWhiteSpace(id))
    {
        return Results.BadRequest(new { detail = "id zorunludur." });
    }

    var removed = siteRegistry.RemoveById(id);
    if (!removed)
    {
        return Results.NotFound(new { detail = "Web kaydi bulunamadi." });
    }

    return Results.Ok(new { removed = true });
}).RequireAuthorization();

app.MapGet("/api/admin/login-attempts", (HttpContext context, IOptionsMonitor<SuperUserOptions> superUserOptions, LoginAttemptTracker loginAttemptTracker) =>
{
    if (!CurrentUserIsSuperUser(context, superUserOptions.CurrentValue))
    {
        return Results.Forbid();
    }

    return Results.Json(loginAttemptTracker.GetRecent(200));
}).RequireAuthorization();

app.MapGet("/", () =>
{
    var pagePath = Path.Combine(app.Environment.ContentRootPath, "index.html");
    return Results.File(pagePath, "text/html; charset=utf-8");
}).RequireAuthorization();

app.MapGet("/index.html", () =>
{
    var pagePath = Path.Combine(app.Environment.ContentRootPath, "index.html");
    return Results.File(pagePath, "text/html; charset=utf-8");
}).RequireAuthorization();

app.Run();

static string SanitizeReturnUrl(string? returnUrl)
{
    if (string.IsNullOrWhiteSpace(returnUrl))
    {
        return "/";
    }

    if (!returnUrl.StartsWith("/", StringComparison.Ordinal) || returnUrl.StartsWith("//", StringComparison.Ordinal))
    {
        return "/";
    }

    return returnUrl;
}

static string GetErrorText(string? errorCode) =>
    errorCode switch
    {
        "invalid" => "Kullanici adi veya parola hatali.",
        "empty" => "Kullanici adi ve parola alanlarini doldurun.",
        "locked" => "Cok fazla hatali deneme. Lutfen bir sure sonra tekrar deneyin.",
        "emailonly" => "Sadece e-posta adresi ile giris yapabilirsiniz.",
        "domain" => "Sadece kurum e-posta uzantisi ile giris yapilabilir.",
        "notallowed" => "Bu hesabin giris yetkisi bulunmuyor.",
        _ => string.Empty,
    };

static string GetClientIp(HttpContext context)
{
    var forwardedFor = context.Request.Headers["X-Forwarded-For"].ToString();
    if (!string.IsNullOrWhiteSpace(forwardedFor))
    {
        return forwardedFor.Split(',')[0].Trim();
    }

    return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}

static bool LooksLikeEmail(string value)
{
    return Regex.IsMatch(value ?? string.Empty, @"^[^\s@]+@[^\s@]+\.[^\s@]+$");
}

static bool IsAllowedEmailDomain(string email, LoginSecurityOptions options)
{
    if (string.IsNullOrWhiteSpace(options.AllowedEmailDomain))
    {
        return true;
    }

    var atIndex = email.LastIndexOf('@');
    if (atIndex < 0 || atIndex == email.Length - 1)
    {
        return false;
    }

    var domain = email[(atIndex + 1)..];
    return string.Equals(domain.Trim(), options.AllowedEmailDomain.Trim(), StringComparison.OrdinalIgnoreCase);
}

static bool IsAllowedLoginEmail(string email, LoginSecurityOptions options)
{
    if (options.AllowedLoginEmails is null || options.AllowedLoginEmails.Count == 0)
    {
        return true;
    }

    return options.AllowedLoginEmails.Any(x => string.Equals(x?.Trim(), email.Trim(), StringComparison.OrdinalIgnoreCase));
}

static bool CurrentUserIsSuperUser(HttpContext context, SuperUserOptions options)
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? "";
    return IsSuperUser(email, options);
}

static bool IsSuperUser(string email, SuperUserOptions options)
{
    if (string.IsNullOrWhiteSpace(email))
    {
        return false;
    }

    return options.Emails.Any(x => string.Equals(x?.Trim(), email.Trim(), StringComparison.OrdinalIgnoreCase));
}
