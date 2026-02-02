using Microsoft.AspNetCore.Mvc.RazorPages;

public class ThrowModel : PageModel
{
    public void OnGet()
    {
        throw new Exception("Test 500 error page");
    }
}
