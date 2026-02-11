using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
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

        // Mirror Register policy
        private static readonly Regex PW_RE =
            new(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$", RegexOptions.Compiled);

        private static readonly Regex STRICT_EMAIL_RE =
            new(@"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", RegexOptions.Compiled);

        private static bool IsValidStrictEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            if (email.Length > 256) return false;
            return STRICT_EMAIL_RE.IsMatch(email);
        }

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
            TempData.Remove("Msg");

            if (Reason == "expired")
            {
                Input.Email = NormalizeEmail(email);
            }
        }

        public async Task<IActionResult> OnPostAsync(string? reason = null)
        {
            Reason = reason;

            // 1) DataAnnotations
            if (!ModelState.IsValid)
                return Page();

            // 2) Normalize what matters
            var isSignedIn = User?.Identity?.IsAuthenticated == true;
            var flow = (!isSignedIn && Reason == "expired")
                ? "expired_prelogin"
                : "normal_signed_in";

            var email = NormalizeEmail(Input.Email);
            var current = Input.CurrentPassword ?? "";
            var newPw = Input.NewPassword ?? "";
            var confirm = Input.ConfirmPassword ?? "";

            // 3) Explicit backend validation (mirror Register)
            if (!isSignedIn && Reason == "expired")
            {
                if (!IsValidStrictEmail(email))
                {
                    // IMPORTANT: must match asp-validation-for="Input.Email"
                    ModelState.AddModelError("Input.Email", "Please enter a valid email address (e.g., name@example.com).");
                }
                else
                {
                    Input.Email = email; // keep normalized
                }
            }

            if (string.IsNullOrWhiteSpace(current))
                // IMPORTANT: must match asp-validation-for="Input.CurrentPassword"
                ModelState.AddModelError("Input.CurrentPassword", "Current password is required.");

            if (string.IsNullOrWhiteSpace(newPw) || !PW_RE.IsMatch(newPw))
                // IMPORTANT: must match asp-validation-for="Input.NewPassword"
                ModelState.AddModelError("Input.NewPassword",
                    "Password must be 12+ chars and include upper/lowercase, number, and symbol.");

            if (!string.Equals(newPw, confirm, StringComparison.Ordinal))
                // IMPORTANT: must match asp-validation-for="Input.ConfirmPassword"
                ModelState.AddModelError("Input.ConfirmPassword", "Passwords do not match.");

            if (!ModelState.IsValid)
            {
                await _audit.LogAsync("CHANGE_PASSWORD_VALIDATION_FAIL", null, $"flow:{flow}; email:{email}");
                return Page();
            }

            IdentityUser? user = null;

            // ===== Identify user =====
            if (isSignedIn)
            {
                user = await _userManager.GetUserAsync(User);
            }
            else if (Reason == "expired")
            {
                user = await _userManager.FindByEmailAsync(email);
            }

            if (user == null)
                return RedirectToPage("/Account/Login");

            await _audit.LogAsync("PASSWORD_CHANGE_ATTEMPT", user.Id, $"flow:{flow}");

            var profile = await _db.MemberProfiles.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (profile == null)
                return RedirectToPage("/Account/Login");

            // ===== Minimum password age =====
            var minAge = TimeSpan.FromMinutes(1);
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
            if (await _policy.IsPasswordReusedAsync(user, newPw))
            {
                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:password_reuse");
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return Page();
            }

            // ===== Verify current password =====
            var currentOk = await _userManager.CheckPasswordAsync(user, current);
            if (!currentOk)
            {
                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:invalid_current_password");

                // Show error under CurrentPassword field
                ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect.");
                ModelState.AddModelError(string.Empty, "Current password is incorrect.");
                return Page();
            }

            // ===== Change password =====
            var result = await _userManager.ChangePasswordAsync(user, current, newPw);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                {
                    // Most common case: password policy errors -> show under NewPassword
                    if (e.Code.Contains("Password", StringComparison.OrdinalIgnoreCase))
                        ModelState.AddModelError("Input.NewPassword", e.Description);

                    else
                        ModelState.AddModelError(string.Empty, e.Description);
                }

                await _audit.LogAsync("CHANGE_PASSWORD_FAIL", user.Id, $"flow:{flow}; reason:identity_error");
                return Page();
            }

            // ===== Record history =====
            await _policy.RecordPasswordAsync(user);
            await _policy.EnforceHistoryLimitAsync(user.Id, keepLastN: 2);

            profile.LastPasswordChangedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync();

            await _audit.LogAsync("PASSWORD_CHANGED", user.Id, $"flow:{flow}; msg:user_changed_password_success");

            if (isSignedIn)
            {
                await _signInManager.RefreshSignInAsync(user);
                TempData["Msg"] = "Password updated successfully.";
                return RedirectToPage("/Index", new { msg = "PasswordChanged" });
            }
            else
            {
                TempData["Msg"] = "Password updated. Please log in again.";
                await _signInManager.SignOutAsync();
                return RedirectToPage("/Account/Login");
            }
        }

        private static string NormalizeEmail(string? email)
            => (email ?? "").Trim().ToLowerInvariant();
    }
}
