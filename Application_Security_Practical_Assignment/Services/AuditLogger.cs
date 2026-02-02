using Application_Security_Practical_Assignment.Data;
using Application_Security_Practical_Assignment.Models;

namespace Application_Security_Practical_Assignment.Services
{
    public class AuditLogger : IAuditLogger
    {
        private readonly ApplicationDbContext _db;
        private readonly IHttpContextAccessor _http;

        public AuditLogger(ApplicationDbContext db, IHttpContextAccessor http)
        {
            _db = db;
            _http = http;
        }

        public async Task LogAsync(string action, string? userId = null, string? details = null)
        {
            var ctx = _http.HttpContext;

            string? ip = ctx?.Connection.RemoteIpAddress?.ToString();
            string? ua = ctx?.Request.Headers["User-Agent"].ToString();
            if (!string.IsNullOrEmpty(ua) && ua.Length > 200) ua = ua.Substring(0, 200);

            var log = new AuditLog
            {
                Action = action,
                UserId = userId,
                Details = details,
                IpAddress = ip,
                UserAgent = ua
            };

            _db.AuditLogs.Add(log);
            await _db.SaveChangesAsync();
        }
    }
}
