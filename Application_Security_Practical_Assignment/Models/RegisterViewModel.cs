using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace Application_Security_Practical_Assignment.Models
{
    public class RegisterViewModel
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; } = "";

        [Required, MaxLength(50)]
        public string LastName { get; set; } = "";

        [Required, MaxLength(20)]
        public string MobileNo { get; set; } = "";

        [Required, MaxLength(200)]
        public string BillingAddress { get; set; } = "";

        // allow special chars: do not filter; output-encode later
        [Required, MaxLength(200)]
        public string ShippingAddress { get; set; } = "";

        [Required]
        public string CreditCardNo { get; set; } = "";

        [Required, EmailAddress]
        public string Email { get; set; } = "";

        // Minimum 12 + upper + lower + number + special
        [Required]
        [MinLength(12, ErrorMessage = "Password must be at least 12 characters.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$",
            ErrorMessage = "Password must contain uppercase, lowercase, number, and special character.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = "";

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Confirm Password does not match Password.")]
        public string ConfirmPassword { get; set; } = "";

        // Photo upload - validate in server logic too (.jpg only)
        public IFormFile? Photo { get; set; }
    }
}
