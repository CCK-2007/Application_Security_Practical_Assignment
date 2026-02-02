namespace Application_Security_Practical_Assignment.Services
{
    public interface IAuditLogger
    {
        Task LogAsync(string action, string? userId = null, string? details = null);
    }
}
