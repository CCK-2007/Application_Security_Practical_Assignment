using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace Application_Security_Practical_Assignment.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;

        public SmtpEmailSender(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendAsync(string to, string subject, string htmlBody)
        {
            var host = _config["Email:SmtpHost"] ?? throw new InvalidOperationException("Email:SmtpHost is missing.");
            var portStr = _config["Email:SmtpPort"] ?? throw new InvalidOperationException("Email:SmtpPort is missing.");
            var from = _config["Email:From"] ?? throw new InvalidOperationException("Email:From is missing.");
            var username = _config["Email:Username"] ?? throw new InvalidOperationException("Email:Username is missing.");
            var password = _config["Email:Password"] ?? throw new InvalidOperationException("Email:Password is missing.");

            if (!int.TryParse(portStr, out var port))
                throw new InvalidOperationException("Email:SmtpPort is not a valid integer.");

            using var msg = new MailMessage
            {
                From = new MailAddress(from),
                Subject = subject,
                Body = htmlBody,
                IsBodyHtml = true
            };
            msg.To.Add(to);

            using var client = new SmtpClient(host, port)
            {
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(username, password),

                // Enforce encrypted SMTP transport (STARTTLS/SSL depending on server)
                EnableSsl = true
            };

            await client.SendMailAsync(msg);
        }
    }
}
