using Application_Security_Practical_Assignment.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_Practical_Assignment.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<MemberProfile> MemberProfiles => Set<MemberProfile>();

        public DbSet<AuditLog> AuditLogs { get; set; } = default!;

        public DbSet<Application_Security_Practical_Assignment.Models.PasswordHistory> PasswordHistories { get; set; }



        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // One profile per user
            builder.Entity<MemberProfile>()
                .HasIndex(p => p.UserId)
                .IsUnique();
        }
    }
}
