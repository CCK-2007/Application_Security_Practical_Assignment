using System.ComponentModel.DataAnnotations;

namespace Application_Security_Practical_Assignment.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; } = "";

        [Required]
        public string PasswordHash { get; set; } = "";

        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    }
}
