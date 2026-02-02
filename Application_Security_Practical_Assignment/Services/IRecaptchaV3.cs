namespace Application_Security_Practical_Assignment.Services

{
    public interface IRecaptchaV3
    {
        Task<(bool ok, double score, string? action)> VerifyAsync(string token, string expectedAction, string? remoteIp);
    }

}
