using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Models;
using Application_Security_Practical_Assignment.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

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
        private readonly IEmailSender _email;
        private readonly IConfiguration _config;

        public RegisterModel(
            UserManager<IdentityUser> userManager,
            ApplicationDbContext db,
            ICreditCardCrypto crypto,
            IWebHostEnvironment env,
            IRecaptchaV3 recaptcha,
            IPasswordPolicyService policy,
            IAuditLogger audit,
            IEmailSender email,
            IConfiguration config)
        {
            _userManager = userManager;
            _db = db;
            _crypto = crypto;
            _env = env;
            _recaptcha = recaptcha;
            _policy = policy;
            _audit = audit;
            _email = email;
            _config = config;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        private static readonly Regex NAME_RE =
            new(@"^[A-Za-z][A-Za-z\s'\-\.]{0,49}$", RegexOptions.Compiled);

        private static readonly Regex MOBILE_RE =
            new(@"^\d{8}$", RegexOptions.Compiled);

        private static readonly Regex CC_RE =
            new(@"^\d{12,16}$", RegexOptions.Compiled);

        private static readonly Regex PW_RE =
            new(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$", RegexOptions.Compiled);

        // stronger email format (rejects ck@g.h)
        private static readonly Regex STRICT_EMAIL_RE =
            new(@"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", RegexOptions.Compiled);

        private static bool IsValidStrictEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            if (email.Length > 256) return false;
            return STRICT_EMAIL_RE.IsMatch(email);
        }

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

            var firstName = NormalizeSpaces(Input.FirstName);
            var lastName = NormalizeSpaces(Input.LastName);
            var email = NormalizeEmail(Input.Email);
            var mobile = (Input.MobileNo ?? "").Trim();
            var billing = NormalizeText(Input.BillingAddress);
            var shipping = NormalizeText(Input.ShippingAddress);
            var cc = (Input.CreditCardNo ?? "").Trim();
            var password = Input.Password ?? "";
            var confirm = Input.ConfirmPassword ?? "";

            if (string.IsNullOrWhiteSpace(firstName) || firstName.Length > 50 || !NAME_RE.IsMatch(firstName))
                ModelState.AddModelError("Input.FirstName", "First name must be 1–50 characters and contain letters/spaces only.");

            if (string.IsNullOrWhiteSpace(lastName) || lastName.Length > 50 || !NAME_RE.IsMatch(lastName))
                ModelState.AddModelError("Input.LastName", "Last name must be 1–50 characters and contain letters/spaces only.");

            if (!IsValidStrictEmail(email))
                ModelState.AddModelError("Input.Email", "Please enter a valid email address (e.g., name@example.com).");

            if (!MOBILE_RE.IsMatch(mobile))
                ModelState.AddModelError("Input.MobileNo", "Mobile number must be exactly 8 digits.");

            if (string.IsNullOrWhiteSpace(billing) || billing.Length > 200 || ContainsDisallowedControlChars(billing))
                ModelState.AddModelError("Input.BillingAddress", "Billing address is required (max 200 chars).");

            if (string.IsNullOrWhiteSpace(shipping) || shipping.Length > 200 || ContainsDisallowedControlChars(shipping))
                ModelState.AddModelError("Input.ShippingAddress", "Shipping address is required (max 200 chars).");

            if (!CC_RE.IsMatch(cc))
                ModelState.AddModelError("Input.CreditCardNo", "Credit card number must be 12–16 digits (numbers only).");
            else if (!PassesLuhn(cc))
                ModelState.AddModelError("Input.CreditCardNo", "Credit card number is invalid.");

            if (string.IsNullOrWhiteSpace(password) || !PW_RE.IsMatch(password))
                ModelState.AddModelError("Input.Password", "Password must be 12+ chars and include upper/lowercase, number, and symbol.");

            if (!string.Equals(password, confirm, StringComparison.Ordinal))
                ModelState.AddModelError("Input.ConfirmPassword", "Confirm Password does not match.");

            if (!ModelState.IsValid)
            {
                await _audit.LogAsync("REGISTER_VALIDATION_FAIL", null, $"email:{email}");
                return Page();
            }

            // reCAPTCHA
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            var (ok, score, action) = await _recaptcha.VerifyAsync(RecaptchaToken ?? "", "register", ip);
            if (!ok)
            {
                await _audit.LogAsync("REGISTER_BOT_BLOCK", null, $"score:{score},action:{action}");
                ModelState.AddModelError(string.Empty, "Suspicious activity detected. Please try again.");
                return Page();
            }

            // unique email
            var existingByEmail = await _userManager.FindByEmailAsync(email);
            if (existingByEmail != null)
            {
                ModelState.AddModelError("Input.Email", "Email is already registered. Please use another email.");
                return Page();
            }

            // photo validation (keep your current logic)
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

            // Create identity user (IMPORTANT: EmailConfirmed = false)
            var user = new IdentityUser
            {
                UserName = email,
                Email = email,
                PhoneNumber = mobile,
                LockoutEnabled = true,
                EmailConfirmed = false
            };

            IdentityResult createResult;
            try
            {
                createResult = await _userManager.CreateAsync(user, password);
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

            // password history
            await _policy.RecordPasswordAsync(user);
            await _policy.EnforceHistoryLimitAsync(user.Id, keepLastN: 2);

            // Encrypt credit card and store profile
            var ccEncrypted = _crypto.EncryptToBase64(cc);

            var profile = new MemberProfile
            {
                UserId = user.Id,
                FirstName = WebUtility.HtmlEncode(firstName),
                LastName = WebUtility.HtmlEncode(lastName),
                BillingAddress = WebUtility.HtmlEncode(billing),
                ShippingAddress = WebUtility.HtmlEncode(shipping),
                MobileNo = mobile,
                CreditCardEncrypted = ccEncrypted,
                PhotoFileName = savedFileName,
                LastPasswordChangedUtc = DateTime.UtcNow,
            };

            _db.MemberProfiles.Add(profile);
            await _db.SaveChangesAsync();

            // ===== SEND CONFIRM EMAIL LINK =====
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encoded = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var relative = Url.Page(
                "/Account/ConfirmEmail",
                pageHandler: null,
                values: new { email = user.Email, token = encoded }
            );

            if (string.IsNullOrWhiteSpace(relative))
                throw new InvalidOperationException("Failed to generate confirm email URL.");

            var publicBaseUrl = _config["App:PublicBaseUrl"];
            if (string.IsNullOrWhiteSpace(publicBaseUrl))
                throw new InvalidOperationException("App:PublicBaseUrl is not configured.");

            if (!Uri.TryCreate(publicBaseUrl, UriKind.Absolute, out var baseUri) ||
                baseUri.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException("App:PublicBaseUrl must be a valid HTTPS URL.");

            var fullLink = new Uri(baseUri, relative).ToString();
            var safeLink = HtmlEncoder.Default.Encode(fullLink);

            await _email.SendAsync(
                user.Email!,
                "Confirm your Bookworms Online email",
                $"""
                <p>Thanks for registering.</p>
                <p><a href="{safeLink}">Click here to confirm your email</a></p>
                <p>If you didn’t create this account, please ignore this email.</p>
                """
            );

            await _audit.LogAsync("REGISTER_SUCCESS", user.Id, "created_account_email_unconfirmed");
            await _audit.LogAsync("EMAIL_CONFIRM_SENT", user.Id, $"email:{email}");

            TempData["RegisterOk"] = "Registration successful. Please check your email to confirm your account before logging in.";
            return RedirectToPage("/Account/Login");
        }

        private static string NormalizeEmail(string? email)
            => (email ?? "").Trim().ToLowerInvariant();

        private static string NormalizeSpaces(string? value)
        {
            value ??= "";
            value = value.Trim();
            value = Regex.Replace(value, @"\s+", " ");
            return value;
        }

        private static string NormalizeText(string? value)
        {
            value ??= "";
            value = value.Trim();
            value = new string(value.Where(c => !char.IsControl(c) || c == '\n' || c == '\r' || c == '\t').ToArray());
            value = Regex.Replace(value, @"[ \t]+", " ");
            return value;
        }

        private static bool ContainsDisallowedControlChars(string value)
            => value.Any(c => char.IsControl(c) && c != '\n' && c != '\r' && c != '\t');

        private static bool PassesLuhn(string digits)
        {
            int sum = 0;
            bool alt = false;

            for (int i = digits.Length - 1; i >= 0; i--)
            {
                int d = digits[i] - '0';
                if (d < 0 || d > 9) return false;

                if (alt)
                {
                    d *= 2;
                    if (d > 9) d -= 9;
                }

                sum += d;
                alt = !alt;
            }

            return (sum % 10) == 0;
        }
    }
}
