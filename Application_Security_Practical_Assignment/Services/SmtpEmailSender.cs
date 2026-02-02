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
            var msg = new MailMessage
            {
                From = new MailAddress(_config["Email:From"]!),
                Subject = subject,
                Body = htmlBody,
                IsBodyHtml = true
            };

            msg.To.Add(to);

            var client = new SmtpClient(
                _config["Email:SmtpHost"],
                int.Parse(_config["Email:SmtpPort"]!)
            )
            {
                Credentials = new NetworkCredential(
                    _config["Email:Username"],
                    _config["Email:Password"]
                ),
                EnableSsl = true
            };

            await client.SendMailAsync(msg);
        }
    }
}
