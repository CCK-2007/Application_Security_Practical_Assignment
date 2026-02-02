using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_Practical_Assignment.Services
{
    public interface IPasswordPolicyService
    {
        Task<bool> IsPasswordReusedAsync(IdentityUser user, string newPlainPassword);
        Task RecordPasswordAsync(IdentityUser user);
        Task EnforceHistoryLimitAsync(string userId, int keepLastN);
    }

    public class PasswordPolicyService : IPasswordPolicyService
    {
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher<IdentityUser> _hasher;

        public PasswordPolicyService(ApplicationDbContext db, IPasswordHasher<IdentityUser> hasher)
        {
            _db = db;
            _hasher = hasher;
        }

        public async Task<bool> IsPasswordReusedAsync(IdentityUser user, string newPlainPassword)
        {
            var last2 = await _db.PasswordHistories
                .Where(x => x.UserId == user.Id)
                .OrderByDescending(x => x.CreatedUtc)
                .Take(2)
                .ToListAsync();

            foreach (var old in last2)
            {
                var vr = _hasher.VerifyHashedPassword(user, old.PasswordHash, newPlainPassword);
                if (vr == PasswordVerificationResult.Success || vr == PasswordVerificationResult.SuccessRehashNeeded)
                    return true;
            }

            return false;
        }

        public async Task RecordPasswordAsync(IdentityUser user)
        {
            if (string.IsNullOrWhiteSpace(user.PasswordHash)) return;

            _db.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash!,
                CreatedUtc = DateTime.UtcNow
            });

            await _db.SaveChangesAsync();
        }

        public async Task EnforceHistoryLimitAsync(string userId, int keepLastN)
        {
            var extra = await _db.PasswordHistories
                .Where(x => x.UserId == userId)
                .OrderByDescending(x => x.CreatedUtc)
                .Skip(keepLastN)
                .ToListAsync();

            if (extra.Count > 0)
            {
                _db.PasswordHistories.RemoveRange(extra);
                await _db.SaveChangesAsync();
            }
        }
    }
}
