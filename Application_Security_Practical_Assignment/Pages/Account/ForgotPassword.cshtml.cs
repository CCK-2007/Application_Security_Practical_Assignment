using System.ComponentModel.DataAnnotations;
using System.Text;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Encodings.Web;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _email;
        private readonly IAuditLogger _audit;
        private readonly string _publicBaseUrl;
        private readonly IConfiguration _config;

        public ForgotPasswordModel(
            UserManager<IdentityUser> userManager,
            IEmailSender email,
            IAuditLogger audit,
            IConfiguration config)
        {
            _userManager = userManager;
            _email = email;
            _audit = audit;

            _config = config;
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

            // 1) Generate RELATIVE path (no host)
            var relative = Url.Page(
                "/Account/ResetPassword",
                pageHandler: null,
                values: new { email = user.Email, token = encodedToken }
            );

            if (string.IsNullOrWhiteSpace(relative))
                throw new InvalidOperationException("Failed to generate reset password URL.");

            // 2) Read TRUSTED base URL from config
            var publicBaseUrl = _config["App:PublicBaseUrl"];
            if (string.IsNullOrWhiteSpace(publicBaseUrl))
                throw new InvalidOperationException("App:PublicBaseUrl is not configured.");

            if (!Uri.TryCreate(publicBaseUrl, UriKind.Absolute, out var baseUri) || baseUri.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException("App:PublicBaseUrl must be a valid HTTPS URL.");

            // 3) Combine to ABSOLUTE HTTPS link
            var fullLink = new Uri(baseUri, relative).ToString();

            // (Optional) encode for safety in HTML attribute
            var safeLink = HtmlEncoder.Default.Encode(fullLink);

            await _email.SendAsync(
                user.Email!,
                "Reset your Bookworms Online password",
                $"""
        <p>You requested a password reset.</p>
        <p><a href="{safeLink}">Click here to reset your password</a></p>
        <p>If you did not request this, please ignore this email.</p>
        """
            );

            await _audit.LogAsync("RESET_EMAIL_SENT", user.Id, "password_reset_link_sent");
            return RedirectToPage("/Account/ForgotPasswordConfirmation");
        }
    }
}
