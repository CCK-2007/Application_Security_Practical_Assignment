using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _email;
        private readonly IAuditLogger _audit;
        private readonly IConfiguration _config;

        private static readonly Regex STRICT_EMAIL_RE =
    new(@"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", RegexOptions.Compiled);

        private static bool IsValidStrictEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            if (email.Length > 256) return false;
            return STRICT_EMAIL_RE.IsMatch(email);
        }


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
            // 1) DataAnnotations server-side validation
            if (!ModelState.IsValid)
                return Page();

            // 2) Normalize
            var email = NormalizeEmail(Email);

            // 3) Explicit backend validation (mirror Register)
            if (!IsValidStrictEmail(email))
            {
                ModelState.AddModelError(nameof(Email), "Please enter a valid email address (e.g., name@example.com).");
            }


            if (!ModelState.IsValid)
            {
                await _audit.LogAsync("FORGOT_PASSWORD_VALIDATION_FAIL", null, $"email:{email}");
                return Page();
            }

            // IMPORTANT: never reveal if email exists
            var user = await _userManager.FindByEmailAsync(email);
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

            if (!Uri.TryCreate(publicBaseUrl, UriKind.Absolute, out var baseUri) ||
                baseUri.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException("App:PublicBaseUrl must be a valid HTTPS URL.");

            // 3) Combine to ABSOLUTE HTTPS link
            var fullLink = new Uri(baseUri, relative).ToString();
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

        private static string NormalizeEmail(string? email)
            => (email ?? "").Trim().ToLowerInvariant();
    }
}
