using System.ComponentModel.DataAnnotations;
using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class TwoFactorModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly IAuditLogger _audit;

        public TwoFactorModel(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            ApplicationDbContext db,
            IAuditLogger audit)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _audit = audit;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public bool RememberMe { get; set; }
        [BindProperty]
        public bool RememberMachine { get; set; } = true;

        public class InputModel
        {
            [Required]
            public string Code { get; set; } = "";
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // get rememberMe from TempData
            RememberMe = TempData["RememberMe"] is bool b && b;

            // ensure there is a 2FA user in progress
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToPage("/Account/Login");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            RememberMe = TempData["RememberMe"] is bool b && b;

            if (!ModelState.IsValid) return Page();

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToPage("/Account/Login");

            var code = (Input.Code ?? "").Replace(" ", "").Replace("-", "");

            var result = await _signInManager.TwoFactorSignInAsync(
                TokenOptions.DefaultEmailProvider,
                code,
                isPersistent: RememberMe,
                rememberClient: false // always false to enforce 2FA each login
            );

            if (result.Succeeded)
            {
                // ✅ Your normal "login success" session setup
                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("Email", user.Email ?? "");
                HttpContext.Session.SetString("LoginTimeUtc", DateTime.UtcNow.ToString("O"));

                var sessionToken = Guid.NewGuid().ToString("N");
                HttpContext.Session.SetString("SessionToken", sessionToken);

                var profile = await _db.MemberProfiles.FirstOrDefaultAsync(p => p.UserId == user.Id);

                // ✅ password expiry enforcement
                var maxAge = TimeSpan.FromMinutes(10); // demo
                if (profile != null)
                {
                    profile.CurrentSessionToken = sessionToken;

                    if (DateTime.UtcNow - profile.LastPasswordChangedUtc > maxAge)
                    {
                        await _db.SaveChangesAsync();

                        await _audit.LogAsync("PASSWORD_EXPIRED", user.Id, $"maxAgeMinutes:{maxAge.TotalMinutes}");
                        await _audit.LogAsync("LOGIN_SUCCESS", user.Id, "2fa_ok,forced_password_change");
                        return RedirectToPage("/Account/ChangePassword", new { reason = "expired" });
                    }

                    await _db.SaveChangesAsync();
                }

                await _audit.LogAsync("LOGIN_SUCCESS", user.Id, "2fa_ok");
                return RedirectToPage("/Index");
            }

            if (result.IsLockedOut)
            {
                await _audit.LogAsync("LOGIN_LOCKOUT", user.Id, "locked_out_during_2fa");
                ModelState.AddModelError(string.Empty, "Account locked due to too many failed attempts.");
                return Page();
            }

            await _audit.LogAsync("2FA_FAIL", user.Id, "invalid_code");
            ModelState.AddModelError(string.Empty, "Invalid verification code.");
            return Page();
        }
    }
}
