using System.Net;
using System.Net.Mail;

namespace RealCordinator.Api.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendResetPasswordEmail(string toEmail, string resetLink)
        {
            var smtpHost = _config["Email:SmtpHost"];
            var smtpPort = int.Parse(_config["Email:SmtpPort"]);
            var smtpUser = _config["Email:Username"];
            var smtpPass = _config["Email:Password"];
            var fromEmail = _config["Email:From"];

            var message = new MailMessage
            {
                From = new MailAddress(fromEmail, "RealCordinator"),
                Subject = "Reset your password",
                Body = $@"
Hello,

You requested a password reset.

Click the link below to reset your password:
{resetLink}

This link will expire in 30 minutes.

If you did not request this, please ignore this email.

— RealCordinator Team
",
                IsBodyHtml = false
            };

            message.To.Add(toEmail);

            var client = new SmtpClient(smtpHost, smtpPort)
            {
                Credentials = new NetworkCredential(smtpUser, smtpPass),
                EnableSsl = true
            };

            await client.SendMailAsync(message);
        }

        public async Task SendVerificationEmail(string toEmail, string verifyLink)
        {
            var smtpHost = _config["Email:SmtpHost"];
            var smtpPort = int.Parse(_config["Email:SmtpPort"]!);
            var smtpUser = _config["Email:Username"];
            var smtpPass = _config["Email:Password"];
            var fromEmail = _config["Email:From"];

            var message = new MailMessage
            {
                From = new MailAddress(fromEmail!, "RealCordinator"),
                Subject = "Verify your email",
                Body = $@"
Hello,

Please verify your email by clicking the link below:

{verifyLink}

This link expires in 24 hours.

— RealCordinator Team
",
                IsBodyHtml = false
            };

            message.To.Add(toEmail);

            var client = new SmtpClient(smtpHost, smtpPort)
            {
                Credentials = new NetworkCredential(smtpUser, smtpPass),
                EnableSsl = true
            };

            await client.SendMailAsync(message);
        }

    }
}
