using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.RegularExpressions;
using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly IPasswordPolicyService _policy;
        private readonly IAuditLogger _audit;

        // Stronger email + mirror password policy (same as Register)
        private static readonly Regex STRICT_EMAIL_RE =
            new(@"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", RegexOptions.Compiled);

        private static readonly Regex PW_RE =
            new(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$", RegexOptions.Compiled);

        public ResetPasswordModel(
            UserManager<IdentityUser> userManager,
            ApplicationDbContext db,
            IPasswordPolicyService policy,
            IAuditLogger audit)
        {
            _userManager = userManager;
            _db = db;
            _policy = policy;
            _audit = audit;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = "";

            [Required]
            public string Token { get; set; } = "";

            [Required, DataType(DataType.Password)]
            public string NewPassword { get; set; } = "";

            [Required, DataType(DataType.Password)]
            [Compare(nameof(NewPassword), ErrorMessage = "Passwords do not match.")]
            public string ConfirmPassword { get; set; } = "";
        }

        public void OnGet(string email, string token)
        {
            Input.Email = email;
            Input.Token = token;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // 1) DataAnnotations
            if (!ModelState.IsValid) return Page();

            // 2) Normalize
            var email = NormalizeEmail(Input.Email);
            var tokenB64 = (Input.Token ?? "").Trim();
            var newPw = Input.NewPassword ?? "";
            var confirm = Input.ConfirmPassword ?? "";

            // 3) Explicit backend validation
            if (!IsValidStrictEmail(email))
                ModelState.AddModelError("Input.Email", "Please enter a valid email address (e.g., name@example.com).");

            if (string.IsNullOrWhiteSpace(tokenB64) || tokenB64.Length > 5000) // sanity limit
                ModelState.AddModelError("Input.Token", "Invalid or expired reset token. Please request a new reset link.");

            if (string.IsNullOrWhiteSpace(newPw) || !PW_RE.IsMatch(newPw))
                ModelState.AddModelError("Input.NewPassword", "Password must be 12+ chars and include upper/lowercase, number, and symbol.");

            if (!string.Equals(newPw, confirm, StringComparison.Ordinal))
                ModelState.AddModelError("Input.ConfirmPassword", "Passwords do not match.");

            if (!ModelState.IsValid)
            {
                await _audit.LogAsync("PASSWORD_RESET_VALIDATION_FAIL", null, $"email:{email}");
                return Page();
            }

            // Find user
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // don't reveal existence
                await _audit.LogAsync("PASSWORD_RESET_FAIL", null, $"user_not_found:{email}");
                return RedirectToPage("/Account/Login");
            }

            // password reuse check
            if (await _policy.IsPasswordReusedAsync(user, newPw))
            {
                await _audit.LogAsync("PASSWORD_RESET_FAIL", user.Id, "password_reuse");
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return Page();
            }

            // Decode token
            string decodedToken;
            try
            {
                decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenB64));
            }
            catch
            {
                await _audit.LogAsync("PASSWORD_RESET_FAIL", user.Id, "invalid_token_format");
                ModelState.AddModelError(string.Empty, "Invalid or expired reset token. Please request a new reset link.");
                return Page();
            }

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, newPw);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);

                await _audit.LogAsync("PASSWORD_RESET_FAIL", user.Id, "identity_error");
                return Page();
            }

            // record password history
            await _policy.RecordPasswordAsync(user);
            await _policy.EnforceHistoryLimitAsync(user.Id, 2);

            // update profile timestamp
            var profile = await _db.MemberProfiles.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (profile != null)
            {
                profile.LastPasswordChangedUtc = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }

            await _audit.LogAsync("PASSWORD_RESET_SUCCESS", user.Id, "reset_password");
            TempData["Msg"] = "Password reset successful. Please log in.";
            return RedirectToPage("/Account/Login");
        }

        private static string NormalizeEmail(string? email)
            => (email ?? "").Trim().ToLowerInvariant();

        private static bool IsValidStrictEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            if (email.Length > 256) return false;
            return STRICT_EMAIL_RE.IsMatch(email);
        }
    }
}
