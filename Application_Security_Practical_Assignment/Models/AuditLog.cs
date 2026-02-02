using System;
using System.ComponentModel.DataAnnotations;

namespace Application_Security_Practical_Assignment.Models
{
    public class AuditLog
    {
        public int AuditLogId { get; set; }

        // Identity user id (nullable for anonymous actions)
        [MaxLength(450)]
        public string? UserId { get; set; }

        [Required, MaxLength(40)]
        public string Action { get; set; } = ""; // e.g. LOGIN_SUCCESS, LOGOUT

        [MaxLength(500)]
        public string? Details { get; set; } // e.g. error info, reason

        [MaxLength(50)]
        public string? IpAddress { get; set; }

        [MaxLength(200)]
        public string? UserAgent { get; set; }

        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    }
}
