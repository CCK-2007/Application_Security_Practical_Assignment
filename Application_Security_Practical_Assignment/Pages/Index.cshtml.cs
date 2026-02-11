using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_Practical_Assignment.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ICreditCardCrypto _crypto;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IAuditLogger _audit;

        public IndexModel(
            ApplicationDbContext db,
            UserManager<IdentityUser> userManager,
            ICreditCardCrypto crypto,
            SignInManager<IdentityUser> signInManager,
            IAuditLogger audit)
        {
            _db = db;
            _userManager = userManager;
            _crypto = crypto;
            _signInManager = signInManager;
            _audit = audit;
        }

        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public string Email { get; set; } = "";
        public string MobileNo { get; set; } = "";
        public string BillingAddress { get; set; } = "";
        public string ShippingAddress { get; set; } = "";
        public string MaskedCard { get; set; } = "";
        public string? PhotoUrl { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // ===== SESSION TIMEOUT CHECK =====
            var sessionUserId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(sessionUserId))
            {
                await _audit.LogAsync("SESSION_EXPIRED", null, "session_timeout");
                await ForceLogoutAsync();

                TempData["Banner"] = "Your session has expired. Please login again.";
                return RedirectToPage("/Account/Login");
            }

            // ===== GET CURRENT USER =====
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                await ForceLogoutAsync();
                return RedirectToPage("/Account/Login");
            }

            Email = user.Email ?? "";

            var profile = await _db.MemberProfiles.AsNoTracking()
                .FirstOrDefaultAsync(p => p.UserId == user.Id);

            if (profile == null)
                return Page();

            // ===== MULTIPLE LOGIN DETECTION =====
            var sessionToken = HttpContext.Session.GetString("SessionToken");

            if (!string.IsNullOrEmpty(profile.CurrentSessionToken) &&
                !string.IsNullOrEmpty(sessionToken) &&
                profile.CurrentSessionToken != sessionToken)
            {
                await _audit.LogAsync("MULTIPLE_LOGIN_DETECTED", user.Id, "session_token_mismatch");
                await ForceLogoutAsync();

                TempData["Banner"] = "Your account was logged in from another device/browser. Please login again.";
                return RedirectToPage("/Account/Login");
            }

            // ===== LOAD USER DATA =====
            FirstName = profile.FirstName;
            LastName = profile.LastName;
            MobileNo = profile.MobileNo;
            BillingAddress = profile.BillingAddress;
            ShippingAddress = profile.ShippingAddress;

            try
            {
                var decrypted = _crypto.DecryptFromBase64(profile.CreditCardEncrypted);
                MaskedCard = MaskCard(decrypted);
            }
            catch
            {
                MaskedCard = "****";
            }

            if (!string.IsNullOrWhiteSpace(profile.PhotoFileName))
                PhotoUrl = "/uploads/" + profile.PhotoFileName;

            return Page();
        }

        private async Task ForceLogoutAsync()
        {
            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();
        }

        private static string MaskCard(string? card)
        {
            card ??= "";
            var digits = new string(card.Where(char.IsDigit).ToArray());
            if (digits.Length < 4) return "****";
            return "**** **** **** " + digits[^4..];
        }
    }
}
