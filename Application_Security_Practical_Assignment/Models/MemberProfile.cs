using System;
using System.ComponentModel.DataAnnotations;

namespace Application_Security_Practical_Assignment.Models
{
    public class MemberProfile
    {
        public int MemberProfileId { get; set; }

        // Link to Identity user
        [Required]
        public string UserId { get; set; } = string.Empty;

        [Required, MaxLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required, MaxLength(50)]
        public string LastName { get; set; } = string.Empty;

        // Keep as string because phone can have leading zeros / country code
        [Required, MaxLength(20)]
  
        [RegularExpression(@"^\d{8}$", ErrorMessage = "Mobile number must be 8 digits.")]
        public string MobileNo { get; set; } = "";

        [Required, MaxLength(200)]
        public string BillingAddress { get; set; } = string.Empty;

        // Allow special chars: do NOT block, just store.
        // Razor output encoding will prevent XSS when displaying.
        [Required, MaxLength(200)]
        public string ShippingAddress { get; set; } = string.Empty;

        // Store encrypted credit card as Base64 string (or use byte[] if you prefer)
        [Required]
        public string CreditCardEncrypted { get; set; } = string.Empty;

        // Store only the saved file name (randomized)
        [MaxLength(255)]
        public string? PhotoFileName { get; set; }

        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

        // Optional but useful for concurrent-login detection later
        [MaxLength(80)]
        public string? CurrentSessionToken { get; set; }

        public DateTime LastPasswordChangedUtc { get; set; } = DateTime.UtcNow;

    }
}
