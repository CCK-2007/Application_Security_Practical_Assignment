using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IAuditLogger _audit;

        public ConfirmEmailModel(UserManager<IdentityUser> userManager, IAuditLogger audit)
        {
            _userManager = userManager;
            _audit = audit;
        }

        public string? Message { get; set; }

        public async Task<IActionResult> OnGetAsync(string? email, string? token)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
                return RedirectToPage("/Account/Login");

            var normalizedEmail = email.Trim().ToLowerInvariant();
            var user = await _userManager.FindByEmailAsync(normalizedEmail);
            if (user == null)
                return RedirectToPage("/Account/Login");

            string decodedToken;
            try
            {
                decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            }
            catch
            {
                await _audit.LogAsync("EMAIL_CONFIRM_FAIL", user.Id, "invalid_token_format");
                Message = "Invalid confirmation link. Please request a new one.";
                return Page();
            }

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if (!result.Succeeded)
            {
                await _audit.LogAsync("EMAIL_CONFIRM_FAIL", user.Id, "confirm_failed");
                Message = "Email confirmation failed or link expired.";
                return Page();
            }

            await _audit.LogAsync("EMAIL_CONFIRMED", user.Id, "email_confirm_success");
            Message = "Email confirmed successfully. You may now log in.";
            return Page();
        }
    }
}
