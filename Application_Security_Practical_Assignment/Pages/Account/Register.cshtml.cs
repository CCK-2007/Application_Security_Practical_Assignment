using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Models;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Net;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly ICreditCardCrypto _crypto;
        private readonly IWebHostEnvironment _env;
        private readonly IRecaptchaV3 _recaptcha;
        private readonly IPasswordPolicyService _policy;
        private readonly IAuditLogger _audit;

        public RegisterModel(
            UserManager<IdentityUser> userManager,
            ApplicationDbContext db,
            ICreditCardCrypto crypto,
            IWebHostEnvironment env,
            IRecaptchaV3 recaptcha,
            IPasswordPolicyService policy,
            IAuditLogger audit)
        {
            _userManager = userManager;
            _db = db;
            _crypto = crypto;
            _env = env;
            _recaptcha = recaptcha;
            _policy = policy;
            _audit = audit;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        public class InputModel
        {
            [Required, MaxLength(50)]
            public string FirstName { get; set; } = "";

            [Required, MaxLength(50)]
            public string LastName { get; set; } = "";

            [Required]
            [StringLength(16, MinimumLength = 12, ErrorMessage = "Credit card number must be 12–16 digits.")]
            [RegularExpression(@"^\d{12,16}$", ErrorMessage = "Credit card number must contain digits only.")]
            public string CreditCardNo { get; set; } = "";

            [Required]
            [RegularExpression(@"^\d{8}$", ErrorMessage = "Mobile number must be 8 digits.")]
            public string MobileNo { get; set; } = "";

            [Required, MaxLength(200)]
            public string BillingAddress { get; set; } = "";

            [Required, MaxLength(200)]
            public string ShippingAddress { get; set; } = "";

            [Required, EmailAddress]
            public string Email { get; set; } = "";

            [Required, DataType(DataType.Password)]
            [MinLength(12)]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$",
                ErrorMessage = "Password must include uppercase, lowercase, number, and special character.")]
            public string Password { get; set; } = "";

            [Required, DataType(DataType.Password)]
            [Compare(nameof(Password), ErrorMessage = "Confirm Password does not match.")]
            public string ConfirmPassword { get; set; } = "";

            public IFormFile? Photo { get; set; }
        }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            // Verify reCAPTCHA v3 token
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            var (ok, score, action) = await _recaptcha.VerifyAsync(RecaptchaToken ?? "", "register", ip);
            if (!ok)
            {
                ModelState.AddModelError(string.Empty, "Suspicious activity detected. Please try again.");
                return Page();
            }

            var normalizedEmail = Input.Email.Trim().ToLowerInvariant();

            // Duplicate check
            var existingByEmail = await _userManager.FindByEmailAsync(normalizedEmail);
            if (existingByEmail != null)
            {
                ModelState.AddModelError("Input.Email", "Email is already registered. Please use another email.");
                return Page();
            }

            // Basic credit card check
            var cc = Input.CreditCardNo.Trim();
            if (cc.Length < 12 || cc.Length > 16)
            {
                ModelState.AddModelError("Input.CreditCardNo", "Credit card number must be between 12 and 16 digits.");
                return Page();
            }

            // PHOTO validation (.JPG only)
            string? savedFileName = null;
            if (Input.Photo is not null && Input.Photo.Length > 0)
            {
                if (Input.Photo.Length > 2 * 1024 * 1024)
                {
                    ModelState.AddModelError("Input.Photo", "Photo must be 2MB or smaller.");
                    return Page();
                }

                var ext = Path.GetExtension(Input.Photo.FileName).ToLowerInvariant();
                if (ext != ".jpg" && ext != ".jpeg")
                {
                    ModelState.AddModelError("Input.Photo", "Only .JPG/.JPEG files are allowed.");
                    return Page();
                }

                if (!string.Equals(Input.Photo.ContentType, "image/jpeg", StringComparison.OrdinalIgnoreCase))
                {
                    ModelState.AddModelError("Input.Photo", "Only JPEG image type is allowed.");
                    return Page();
                }

                using (var stream = Input.Photo.OpenReadStream())
                {
                    if (stream.Length < 2)
                    {
                        ModelState.AddModelError("Input.Photo", "Invalid JPEG file.");
                        return Page();
                    }
                    int b1 = stream.ReadByte();
                    int b2 = stream.ReadByte();
                    if (b1 != 0xFF || b2 != 0xD8)
                    {
                        ModelState.AddModelError("Input.Photo", "Invalid JPEG file signature.");
                        return Page();
                    }
                }

                var uploadsDir = Path.Combine(_env.WebRootPath, "uploads");
                Directory.CreateDirectory(uploadsDir);

                savedFileName = $"{Guid.NewGuid():N}.jpg";
                var filePath = Path.Combine(uploadsDir, savedFileName);

                using var fileStream = System.IO.File.Create(filePath);
                await Input.Photo.CopyToAsync(fileStream);
            }

            // Create identity user
            var user = new IdentityUser
            {
                UserName = normalizedEmail,
                Email = normalizedEmail,
                PhoneNumber = Input.MobileNo.Trim(),
                LockoutEnabled = true,
                EmailConfirmed = true // ✅ as per your request ("trust email is true")
            };

            IdentityResult createResult;
            try
            {
                createResult = await _userManager.CreateAsync(user, Input.Password);
            }
            catch (DbUpdateException)
            {
                ModelState.AddModelError("Input.Email", "Email is already registered. Please use another email.");
                return Page();
            }

            if (!createResult.Succeeded)
            {
                foreach (var err in createResult.Errors)
                    ModelState.AddModelError(string.Empty, err.Description);
                return Page();
            }

            await _policy.RecordPasswordAsync(user);
            await _policy.EnforceHistoryLimitAsync(user.Id, keepLastN: 2);

            // ❌ Do NOT enable 2FA here; we'll enforce at login
            await _audit.LogAsync("REGISTER_SUCCESS", user.Id, "created_account_single_form");

            // Encrypt credit card
            var ccEncrypted = _crypto.EncryptToBase64(cc);

            // Save profile
            var profile = new MemberProfile
            {
                UserId = user.Id,
                FirstName = WebUtility.HtmlEncode(CleanText(Input.FirstName)),
                LastName = WebUtility.HtmlEncode(CleanText(Input.LastName)),
                BillingAddress = WebUtility.HtmlEncode(CleanText(Input.BillingAddress)),
                ShippingAddress = WebUtility.HtmlEncode(CleanText(Input.ShippingAddress)),
                MobileNo = Input.MobileNo.Trim(),
                CreditCardEncrypted = ccEncrypted,
                PhotoFileName = savedFileName,
                LastPasswordChangedUtc = DateTime.UtcNow,
            };

            _db.MemberProfiles.Add(profile);
            await _db.SaveChangesAsync();

            TempData["RegisterOk"] = "Registration successful. Please log in.";
            return RedirectToPage("/Account/Login");
        }

        private static string CleanText(string? value)
        {
            value ??= "";
            value = value.Trim();
            value = new string(value.Where(c => !char.IsControl(c) || c == '\n' || c == '\r' || c == '\t').ToArray());
            while (value.Contains("  "))
                value = value.Replace("  ", " ");
            return value;
        }
    }
}
