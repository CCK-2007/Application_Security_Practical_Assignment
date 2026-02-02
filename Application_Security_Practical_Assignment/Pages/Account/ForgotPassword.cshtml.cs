using System.ComponentModel.DataAnnotations;
using System.Text;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _email;
        private readonly IAuditLogger _audit;
        private readonly string _publicBaseUrl;

        public ForgotPasswordModel(
            UserManager<IdentityUser> userManager,
            IEmailSender email,
            IAuditLogger audit,
            IConfiguration config)
        {
            _userManager = userManager;
            _email = email;
            _audit = audit;

            _publicBaseUrl = config["App:PublicBaseUrl"]
                ?? throw new InvalidOperationException("Missing App:PublicBaseUrl in configuration.");
        }

        [BindProperty]
        [Required, EmailAddress]
        public string Email { get; set; } = "";

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Email.Trim().ToLower());

            if (user == null)
            {
                await _audit.LogAsync("RESET_REQUEST", null, "email_not_found");
                return RedirectToPage("/Account/ForgotPasswordConfirmation");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            // 1) Generate RELATIVE path only (does not use request host)
            var relative = Url.Page(
                "/Account/ResetPassword",
                pageHandler: null,
                values: new { email = user.Email, token = encodedToken }
            );

            if (string.IsNullOrWhiteSpace(relative))
                throw new InvalidOperationException("Failed to generate reset password URL.");

            // 2) Combine with trusted base URL (prevents Host header injection)
            var baseUri = new Uri(_publicBaseUrl.TrimEnd('/') + "/");
            var link = new Uri(baseUri, relative.TrimStart('/')).ToString();

            await _email.SendAsync(
                user.Email!,
                "Reset your Bookworms Online password",
                $"""
                <p>You requested a password reset.</p>
                <p>
                  <a href="{link}">Click here to reset your password</a>
                </p>
                <p>If you did not request this, please ignore this email.</p>
                """
            );

            await _audit.LogAsync("RESET_EMAIL_SENT", user.Id, "password_reset_link_sent");
            return RedirectToPage("/Account/ForgotPasswordConfirmation");
        }
    }
}
