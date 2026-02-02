using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IAuditLogger _audit;

        public LogoutModel(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IAuditLogger audit)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _audit = audit;
        }

        public void OnGet()
        {
            // Show confirmation page
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            await _audit.LogAsync("LOGOUT", user?.Id, "user_clicked_logout");

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();

            return RedirectToPage("/Account/Login");
        }
    }
}
