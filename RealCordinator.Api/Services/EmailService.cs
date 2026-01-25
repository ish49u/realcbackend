using SendGrid;
using SendGrid.Helpers.Mail;

namespace RealCordinator.Api.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendVerificationEmail(string toEmail, string verifyLink)
        {
            var apiKey = _config["SENDGRID_API_KEY"];
            var fromEmail = _config["FROM_EMAIL"];

            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(fromEmail))
                throw new Exception("SendGrid configuration missing");

            var client = new SendGridClient(apiKey);

            var from = new EmailAddress(fromEmail, "RealCordinator");
            var to = new EmailAddress(toEmail);

            var subject = "Verify your email";
            var plainText = $"Please verify your email:\n\n{verifyLink}";
            var html = $"<p>Please verify your email:</p><a href='{verifyLink}'>Verify Email</a>";

            var msg = MailHelper.CreateSingleEmail(
                from,
                to,
                subject,
                plainText,
                html
            );

            var response = await client.SendEmailAsync(msg);

            if ((int)response.StatusCode >= 400)
            {
                throw new Exception("SendGrid verification email failed");
            }
        }

        public async Task SendResetPasswordEmail(string toEmail, string resetLink)
        {
            var apiKey = _config["SENDGRID_API_KEY"];
            var fromEmail = _config["FROM_EMAIL"];

            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(fromEmail))
                throw new Exception("SendGrid configuration missing");

            var client = new SendGridClient(apiKey);

            var from = new EmailAddress(fromEmail, "RealCordinator");
            var to = new EmailAddress(toEmail);

            var subject = "Reset your password";
            var plainText = $"Reset your password:\n\n{resetLink}";
            var html = $"<p>Reset your password:</p><a href='{resetLink}'>Reset Password</a>";

            var msg = MailHelper.CreateSingleEmail(
                from,
                to,
                subject,
                plainText,
                html
            );

            var response = await client.SendEmailAsync(msg);

            if ((int)response.StatusCode >= 400)
            {
                throw new Exception("SendGrid reset email failed");
            }
        }
    }
}
