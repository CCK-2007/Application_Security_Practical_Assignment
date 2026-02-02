using System.Text.Json;

namespace Application_Security_Practical_Assignment.Services

{

    public class RecaptchaV3 : IRecaptchaV3
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _config;

        public RecaptchaV3(IHttpClientFactory httpClientFactory, IConfiguration config)
        {
            _httpClientFactory = httpClientFactory;
            _config = config;
        }

        public async Task<(bool ok, double score, string? action)> VerifyAsync(string token, string expectedAction, string? remoteIp)
        {
            var secret = _config["Recaptcha:SecretKey"];
            var minScore = double.TryParse(_config["Recaptcha:MinimumScore"], out var ms) ? ms : 0.5;

            if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(token))
                return (false, 0, null);

            var client = _httpClientFactory.CreateClient();
            var form = new Dictionary<string, string>
            {
                ["secret"] = secret,
                ["response"] = token
            };

            if (!string.IsNullOrWhiteSpace(remoteIp))
                form["remoteip"] = remoteIp;

            var resp = await client.PostAsync(
                "https://www.google.com/recaptcha/api/siteverify",
                new FormUrlEncodedContent(form));

            resp.EnsureSuccessStatusCode();

            using var stream = await resp.Content.ReadAsStreamAsync();
            var json = await JsonDocument.ParseAsync(stream);

            bool success = json.RootElement.GetProperty("success").GetBoolean();
            double score = json.RootElement.TryGetProperty("score", out var s) ? s.GetDouble() : 0;
            string? action = json.RootElement.TryGetProperty("action", out var a) ? a.GetString() : null;

            bool ok = success
                      && string.Equals(action, expectedAction, StringComparison.OrdinalIgnoreCase)
                      && score >= minScore;

            return (ok, score, action);
        }
    }

}
