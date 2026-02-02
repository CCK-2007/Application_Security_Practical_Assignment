using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Application_Security_Practical_Assignment.Services;
using System.Security.Claims;

namespace Application_Security_Practical_Assignment.Pages
{
    public class StatusCodeModel : PageModel
    {
        private readonly IAuditLogger _audit;

        public StatusCodeModel(IAuditLogger audit)
        {
            _audit = audit;
        }

        [BindProperty(SupportsGet = true)]
        public int Code { get; set; }

        public async Task OnGetAsync()
        {
            var userId = User?.Identity?.IsAuthenticated == true
                ? User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                : null;

            // IMPORTANT: after re-execute, the original URL is stored here
            var originalPath = HttpContext.Features.Get<
                Microsoft.AspNetCore.Diagnostics.IStatusCodeReExecuteFeature>()?.OriginalPath;

            await _audit.LogAsync(
                action: $"HTTP_{Code}",
                userId: userId,
                details: $"path:{originalPath ?? HttpContext.Request.Path}"
            );
        }
    }
}
