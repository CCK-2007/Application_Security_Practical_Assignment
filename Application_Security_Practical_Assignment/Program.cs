using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;


var builder = WebApplication.CreateBuilder(args);

// Razor Pages
builder.Services.AddRazorPages(options =>
{
    // Automatically validates antiforgery token on all POST/PUT/DELETE (Razor Pages)
    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
});

// SQL Server + EF Core
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity (Unique email + password rules + lockout)
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
{
    options.User.RequireUniqueEmail = true;

    options.SignIn.RequireConfirmedEmail = true;

    options.Password.RequiredLength = 12;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireDigit = true;
    options.Password.RequireNonAlphanumeric = true;

    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// force login path for unauthorized access
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";

    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);

});


// Register the encryption service in Program.cs
builder.Services.AddScoped<Application_Security_Practical_Assignment.Services.ICreditCardCrypto,
    Application_Security_Practical_Assignment.Services.AesCreditCardCrypto>();

// Register the audit logger service in Program.cs
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<Application_Security_Practical_Assignment.Services.IAuditLogger,
                          Application_Security_Practical_Assignment.Services.AuditLogger>();


// Register the reCAPTCHA service in Program.cs
builder.Services.AddHttpClient();
builder.Services.AddScoped<IRecaptchaV3, RecaptchaV3>();

// Register the password policy service in Program.cs
builder.Services.AddScoped<IPasswordPolicyService, PasswordPolicyService>();

// Register the email sender service in Program.cs
builder.Services.AddScoped<IEmailSender, SmtpEmailSender>();


var app = builder.Build();

// Global exception handling + audit logging
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        // Create scope so we can resolve scoped services like IAuditLogger
        using var scope = app.Services.CreateScope();
        var audit = scope.ServiceProvider.GetRequiredService<Application_Security_Practical_Assignment.Services.IAuditLogger>();

        var userId = context.User?.Identity?.IsAuthenticated == true
            ? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            : null;

        // DO NOT log sensitive data. Log type + path, not stack trace to DB.
        await audit.LogAsync(
            "UNHANDLED_EXCEPTION",
            userId,
            $"path:{context.Request.Path}; type:{ex.GetType().Name}"
        );

        throw; // rethrow so UseExceptionHandler can show /Error
    }
});

app.UseExceptionHandler("/Error");
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

//if (!app.Environment.IsDevelopment())
//{
//    app.UseExceptionHandler("/Error");
//    app.UseHsts();
//}

app.UseHttpsRedirection();

//This block adds security headers to every HTTP response your application sends.
//It hardens your web application against XSS, clickjacking, MIME-type attacks, and data leakage at the browser level.
//Which “Prevent XSS, proper input handling, and application security hardening” 
app.Use(async (context, next) =>
{
    // Prevent MIME sniffing
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";

    // Clickjacking protection
    context.Response.Headers["X-Frame-Options"] = "DENY";

    // Reduce info leakage
    context.Response.Headers["Referrer-Policy"] = "no-referrer";

    // Basic XSS mitigation (modern browsers rely mostly on CSP)
    context.Response.Headers["X-XSS-Protection"] = "0";

    // Content Security Policy 
    // Allows: self resources + bootstrap CDN + Google reCAPTCHA resources
    context.Response.Headers["Content-Security-Policy"] =
     "default-src 'self'; " +
     "img-src 'self' data: https://www.gstatic.com https://www.google.com; " +
     "style-src 'self' 'unsafe-inline'; " +
     "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; " +
     "connect-src 'self' https://www.google.com https://www.gstatic.com; " +
     "frame-src https://www.google.com; " +
     "object-src 'none'; " +
     "base-uri 'self'; " +
     "frame-ancestors 'none'";


    await next();
});

app.UseStaticFiles();

app.UseRouting();

app.UseSession();

// Session Timeout Middleware, after session timeout, sign out user and redirect to login page
app.Use(async (context, next) =>
{
    // Only check authenticated users
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var sessionUser = context.Session.GetString("UserId");

        // Session expired but cookie still valid
        if (string.IsNullOrEmpty(sessionUser))
        {
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);

            context.Response.Redirect("/Account/Login?timeout=true");
            return;
        }
    }

    await next();
});

app.UseAuthentication();   // required for Identity
app.UseAuthorization();


app.UseStatusCodePagesWithReExecute("/StatusCode", "?code={0}");

app.MapRazorPages();
app.Run();
