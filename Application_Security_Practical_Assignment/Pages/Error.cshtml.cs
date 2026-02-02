using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Application_Security_Practical_Assignment.Services;
using System.Security.Claims;

namespace Application_Security_Practical_Assignment.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]
    public class ErrorModel : PageModel
    {
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        private readonly ILogger<ErrorModel> _logger;
        private readonly IAuditLogger _audit;

        public ErrorModel(ILogger<ErrorModel> logger, IAuditLogger audit)
        {
            _logger = logger;
            _audit = audit;
        }

        public async Task OnGetAsync()
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;

            // user might be null if not logged in
            var userId = User?.Identity?.IsAuthenticated == true
                ? User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                : null;

            // Optional: log that the error page was shown (not the full exception)
            await _audit.LogAsync("ERROR_PAGE_SHOWN", userId, $"requestId:{RequestId}");
        }
    }
}
