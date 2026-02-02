using System.ComponentModel.DataAnnotations;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;


namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _email;
        private readonly IAuditLogger _audit;

        public ForgotPasswordModel(
            UserManager<IdentityUser> userManager,
            IEmailSender email,
            IAuditLogger audit)
        {
            _userManager = userManager;
            _email = email;
            _audit = audit;
        }

        [BindProperty]
        [Required, EmailAddress]
        public string Email { get; set; } = "";

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Email.Trim().ToLower());

            // IMPORTANT: do NOT reveal whether email exists
            if (user == null)
            {
                await _audit.LogAsync("RESET_REQUEST", null, "email_not_found");
                return RedirectToPage("/Account/ForgotPasswordConfirmation");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // encode token for URL
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var link = Url.Page(
                "/Account/ResetPassword",
                pageHandler: null,
                values: new { email = user.Email, token = encodedToken },
                protocol: "https"   // force HTTPS, instead of Request.Scheme
            );


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
