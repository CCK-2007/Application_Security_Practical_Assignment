using System.ComponentModel.DataAnnotations;
using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    // IMPORTANT: Do NOT [Authorize] so "expired" users can access this page pre-login
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ApplicationDbContext _db;
        private readonly IPasswordPolicyService _policy;
        private readonly IAuditLogger _audit;

        public ChangePasswordModel(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ApplicationDbContext db,
            IPasswordPolicyService policy,
            IAuditLogger audit)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _policy = policy;
            _audit = audit;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            // Used for expired flow (pre-login)
            [EmailAddress]
            public string? Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string CurrentPassword { get; set; } = "";

            [Required]
            [DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters.")]
            [RegularExpression(
                @"^.*(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).*$",
                ErrorMessage = "Password must include uppercase, lowercase, number, and symbol."
            )]
            public string NewPassword { get; set; } = "";

            [Required]
            [DataType(DataType.Password)]
            [Compare(nameof(NewPassword), ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; } = "";
        }

        public string? Reason { get; set; }

        public void OnGet(string? reason = null, string? email = null)
        {
            Reason = reason;

            // : Clear any old success TempData that might leak into this page
            // (Success message should only be shown on Login page after redirect)
            TempData.Remove("Msg");

            if (Reason == "expired")
            {
                Input.Email = (email ?? "").Trim().ToLowerInvariant();
            }
        }

        public async Task<IActionResult> OnPostAsync(string? reason = null)
        {
            Reason = reason;

            if (!ModelState.IsValid)
                return Page();

            IdentityUser? user = null;
            var isSignedIn = User?.Identity?.IsAuthenticated == true;

            // Determine flow for audit / redirect decisions
            var flow = (!isSignedIn && Reason == "expired")
                ? "expired_prelogin"
                : "normal_signed_in";

            // ===== Identify user =====
            if (isSignedIn)
            {
                user = await _userManager.GetUserAsync(User);
            }
            else if (Reason == "expired")
            {
                var email = (Input.Email ?? "").Trim().ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(email))
                {
                    ModelState.AddModelError(string.Empty, "Missing email. Please log in again.");
                    return Page();
                }

                user = await _userManager.FindByEmailAsync(email);
            }

            if (user == null)
                return RedirectToPage("/Account/Login");

            await _audit.LogAsync("PASSWORD_CHANGE_ATTEMPT", user.Id, $"flow:{flow}");

            var profile = await _db.MemberProfiles.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (profile == null)
                return RedirectToPage("/Account/Login");

            // ===== Minimum password age =====
            var minAge = TimeSpan.FromMinutes(5);
            var timeSinceLast = DateTime.UtcNow - profile.LastPasswordChangedUtc;

            if (timeSinceLast < minAge)
            {
                var remaining = minAge - timeSinceLast;
                var mins = (int)Math.Ceiling(remaining.TotalMinutes);

                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:min_age; remaining_minutes:{mins}");
                ModelState.AddModelError(string.Empty, $"You changed your password recently. Please try again in {mins} minute(s).");
                return Page();
            }

            // ===== Password reuse check =====
            if (await _policy.IsPasswordReusedAsync(user, Input.NewPassword))
            {
                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:password_reuse");
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return Page();
            }

            // ===== Verify current password =====
            var currentOk = await _userManager.CheckPasswordAsync(user, Input.CurrentPassword);
            if (!currentOk)
            {
                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:invalid_current_password");
                ModelState.AddModelError(string.Empty, "Current password is incorrect.");
                return Page();
            }

            // ===== Change password =====
            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);

                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:identity_error");
                return Page();
            }

            // ===== Record history =====
            await _policy.RecordPasswordAsync(user);
            await _policy.EnforceHistoryLimitAsync(user.Id, keepLastN: 2);

            profile.LastPasswordChangedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync();

            await _audit.LogAsync("PASSWORD_CHANGED", user.Id, $"flow:{flow}; msg:user_changed_password_success");

            // IMPORTANT: Decide redirect based on flow
            if (isSignedIn)
            {
                // Keep the user logged in after changing password
                await _signInManager.RefreshSignInAsync(user);
                TempData["Msg"] = "Password updated successfully.";
                return RedirectToPage("/Index", new { msg = "PasswordChanged" });
            }
            else
            {
                // Expired pre-login flow: force a fresh login + 2FA
                TempData["Msg"] = "Password updated. Please log in again.";
                await _signInManager.SignOutAsync(); // safe even if not signed in
                return RedirectToPage("/Account/Login");
            }
        }


    }
}
