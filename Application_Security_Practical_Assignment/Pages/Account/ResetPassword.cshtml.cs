using System.ComponentModel.DataAnnotations;
using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;


namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly IPasswordPolicyService _policy;
        private readonly IAuditLogger _audit;

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

        [Required]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters.")]
        [RegularExpression(@"^.*(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).*$",
            ErrorMessage = "Password must include uppercase, lowercase, number, and symbol.")]
        public string NewPassword { get; set; } = "";

        [Required]
        [DataType(DataType.Password)]
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

            if (!ModelState.IsValid) return Page();

            var email = Input.Email.Trim().ToLowerInvariant();
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return RedirectToPage("/Account/Login");

            // password reuse check
            if (await _policy.IsPasswordReusedAsync(user, Input.NewPassword))
            {
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return Page();
            }

            string decodedToken;
            try
            {
                decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Input.Token));
            }
            catch
            {
                ModelState.AddModelError(string.Empty, "Invalid or expired reset token. Please request a new reset link.");
                await _audit.LogAsync("PASSWORD_RESET_FAIL", user.Id, "invalid_token_format");
                return Page();
            }

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, Input.NewPassword);

            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);
                return Page();
            }

            // record password history
            await _policy.RecordPasswordAsync(user);
            await _policy.EnforceHistoryLimitAsync(user.Id, 2);

            // update last changed timestamp (safe)
            var profile = await _db.MemberProfiles.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (profile != null)
            {
                profile.LastPasswordChangedUtc = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }

            await _audit.LogAsync("PASSWORD_RESET_SUCCESS", user.Id, "reset_password");
            return RedirectToPage("/Account/Login");
        }

    }
}
