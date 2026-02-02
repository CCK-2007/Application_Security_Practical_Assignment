using Microsoft.AspNetCore.Mvc.RazorPages;
using Application_Security_Practical_Assignment.Services;
using System.Security.Claims;

namespace Application_Security_Practical_Assignment.Pages.Account
{
    public class AccessDeniedModel : PageModel
    {
        private readonly IAuditLogger _audit;

        public AccessDeniedModel(IAuditLogger audit)
        {
            _audit = audit;
        }

        public async Task OnGetAsync()
        {
            var userId = User?.Identity?.IsAuthenticated == true
                ? User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                : null;

            await _audit.LogAsync("ACCESS_DENIED", userId, $"path:{HttpContext.Request.Path}");
        }
    }
}
