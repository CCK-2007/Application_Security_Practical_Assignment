using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;


namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly IAuditLogger _audit;
        private readonly IRecaptchaV3 _recaptcha;
        private readonly IEmailSender _email;



        public LoginModel(
             SignInManager<IdentityUser> signInManager,
             UserManager<IdentityUser> userManager,
             ApplicationDbContext db,
             IAuditLogger audit,
             IRecaptchaV3 recaptcha,
             IEmailSender email)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _audit = audit;
            _recaptcha = recaptcha;
            _email = email;
        }


        [BindProperty]
        public InputModel Input { get; set; } = new();


        [BindProperty]
        public string? RecaptchaToken { get; set; }


        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = "";

            [Required, DataType(DataType.Password)]
            public string Password { get; set; } = "";

            public bool RememberMe { get; set; } = false;
        }

        public IActionResult OnGet(bool? timeout = null)
        {
            if (timeout == true)
                ModelState.AddModelError(string.Empty, "Your session has expired. Please log in again.");

            if (User.Identity?.IsAuthenticated == true)
                return RedirectToPage("/Index");

            return Page();
        }


        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            // Verify reCAPTCHA v3 token
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            var (ok, score, action) = await _recaptcha.VerifyAsync(RecaptchaToken ?? "", "login", ip);

            if (!ok)
            {
                await _audit.LogAsync("LOGIN_BOT_BLOCK", null, $"score:{score},action:{action}");
                ModelState.AddModelError(string.Empty, "Suspicious activity detected. Please try again.");
                return Page();
            }

            var email = Input.Email.Trim().ToLowerInvariant();

            // Find user
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                await _audit.LogAsync("LOGIN_FAIL", null, $"email_not_found:{email}");
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return Page();
            }

            // ✅ Step 0: Ensure email is confirmed and verified in user's email
            if (!user.EmailConfirmed)
            {
                await _audit.LogAsync("LOGIN_FAIL", user.Id, "email_not_confirmed");
                ModelState.AddModelError(string.Empty, "Please verify your email before logging in.");
                return Page();
            }

            // ✅ Step 1: Verify password WITHOUT signing in yet (prevents auth cookie creation)
            var pwCheck = await _signInManager.CheckPasswordSignInAsync(
                user,
                Input.Password,
                lockoutOnFailure: true
            );

            if (pwCheck.IsLockedOut)
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);

                string msg = "Account locked due to multiple failed login attempts. Please try again later.";
                if (lockoutEnd.HasValue)
                {
                    var remaining = lockoutEnd.Value.UtcDateTime - DateTime.UtcNow;
                    if (remaining.TotalSeconds > 0)
                    {
                        var mins = (int)Math.Ceiling(remaining.TotalMinutes);
                        msg = $"Account locked due to multiple failed login attempts. Please try again in {mins} minute(s).";
                    }
                }

                await _audit.LogAsync("LOGIN_LOCKOUT", user.Id, $"lockout_until_utc:{lockoutEnd:O}");
                ModelState.AddModelError(string.Empty, msg);
                return Page();
            }

            if (!pwCheck.Succeeded)
            {
                await _audit.LogAsync("LOGIN_FAIL", user.Id, "invalid_password");
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return Page();
            }

            // ✅ Step Check password expiry BEFORE 2FA and BEFORE sign-in
            var profile = await _db.MemberProfiles
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.UserId == user.Id);

            var maxAge = TimeSpan.FromMinutes(1);

            if (profile != null && DateTime.UtcNow - profile.LastPasswordChangedUtc > maxAge)
            {
                await _audit.LogAsync("PASSWORD_EXPIRED", user.Id, $"maxAgeMinutes:{maxAge.TotalMinutes}");

                // IMPORTANT: Do not start 2FA, do not sign in
                return RedirectToPage("/Account/ChangePassword", new { reason = "expired", email });
            }

            // ✅ Step 3: Ensure 2FA is enabled (only after passing expiry check)
            if (!user.TwoFactorEnabled)
            {
                user.TwoFactorEnabled = true;
                await _userManager.UpdateAsync(user);
            }

            // Mandatory 2FA: do NOT allow remembered device to bypass OTP
            await HttpContext.SignOutAsync(IdentityConstants.TwoFactorRememberMeScheme);

            // ✅ Step 4: Now do real sign-in (this is where auth cookie / 2FA flow begins)
            var result = await _signInManager.PasswordSignInAsync(
                userName: user.UserName!,
                password: Input.Password,
                isPersistent: Input.RememberMe,
                lockoutOnFailure: true
            );

            if (result.RequiresTwoFactor)
            {
                var code = await _userManager.GenerateTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultEmailProvider
                );

                await _email.SendAsync(
                    user.Email!,
                    "Your Bookworms Online login code",
                    $"""
            <p>Your login verification code is:</p>
            <h2>{code}</h2>
            <p>This code will expire shortly. If you didn’t try to sign in, please ignore.</p>
            """
                );

                await _audit.LogAsync("2FA_CODE_SENT", user.Id, $"email:{email}");

                return RedirectToPage("/Account/TwoFactor", new { rememberMe = Input.RememberMe });
            }

            if (result.Succeeded)
            {
                // ✅ Only here user is authenticated, so session stuff is safe
                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("Email", user.Email ?? "");
                HttpContext.Session.SetString("LoginTimeUtc", DateTime.UtcNow.ToString("O"));

                var sessionToken = Guid.NewGuid().ToString("N");
                HttpContext.Session.SetString("SessionToken", sessionToken);

                // Update current session token in DB (not required for login, but for multi-login detection)
                var profileToUpdate = await _db.MemberProfiles
                    .FirstOrDefaultAsync(p => p.UserId == user.Id);

                if (profileToUpdate != null)
                {
                    profileToUpdate.CurrentSessionToken = sessionToken;
                    await _db.SaveChangesAsync();
                }

                await _audit.LogAsync("LOGIN_SUCCESS", user.Id, $"email:{email}");
                return RedirectToPage("/Index");
            }

            if (result.IsLockedOut)
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);

                string msg = "Account locked due to multiple failed login attempts. Please try again later.";
                if (lockoutEnd.HasValue)
                {
                    var remaining = lockoutEnd.Value.UtcDateTime - DateTime.UtcNow;
                    if (remaining.TotalSeconds > 0)
                    {
                        var mins = (int)Math.Ceiling(remaining.TotalMinutes);
                        msg = $"Account locked due to multiple failed login attempts. Please try again in {mins} minute(s).";
                    }
                }

                await _audit.LogAsync("LOGIN_LOCKOUT", user.Id, $"lockout_until_utc:{lockoutEnd:O}");
                ModelState.AddModelError(string.Empty, msg);
                return Page();
            }

            await _audit.LogAsync("LOGIN_FAIL", user.Id, "unknown_failure");
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return Page();
        }

    }
}
