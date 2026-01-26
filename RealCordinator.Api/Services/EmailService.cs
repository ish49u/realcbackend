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

        public async Task SendEmailVerificationCode(string toEmail, string code)
        {
            var apiKey = _config["SENDGRID_API_KEY"];
            var fromEmail = _config["FROM_EMAIL"];

            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(fromEmail))
                throw new Exception("SendGrid configuration missing");

            var client = new SendGridClient(apiKey);

            var from = new EmailAddress(fromEmail, "RealCordinator");
            var to = new EmailAddress(toEmail);

            var subject = "Verify your email address";

            var html = $@"
    <div style='font-family:Arial, sans-serif;'>
        <h2>Email Verification</h2>
        <p>Use the following code to verify your email:</p>

        <h1 style='letter-spacing:6px; color:#dc2626;'>{code}</h1>

        <p style='font-size:12px; color:#666;'>
            This code will expire in 10 minutes.
        </p>
    </div>";

            var msg = MailHelper.CreateSingleEmail(
                from,
                to,
                subject,
                code,
                html
            );

            var response = await client.SendEmailAsync(msg);

            if ((int)response.StatusCode >= 400)
                throw new Exception("SendGrid verification code email failed");
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
            var html = $@"
<div style='font-family:Arial, sans-serif;'>
    <h2>Reset your password</h2>
    <p>Click the button below to reset your password:</p>

    <a href='{resetLink}'
       style='display:inline-block;
              padding:12px 20px;
              background-color:#dc2626;
              color:#ffffff;
              text-decoration:none;
              border-radius:6px;
              font-weight:bold;'>
        Reset Password
    </a>

    <p style='margin-top:16px; font-size:12px; color:#666;'>
        This link will expire in 30 minutes.
    </p>
</div>";

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
        public async Task SendResetCodeEmail(string toEmail, string code)
        {
            var apiKey = _config["SENDGRID_API_KEY"];
            var fromEmail = _config["FROM_EMAIL"];

            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(fromEmail))
                throw new Exception("SendGrid configuration missing");

            var client = new SendGridClient(apiKey);

            var from = new EmailAddress(fromEmail, "RealCordinator");
            var to = new EmailAddress(toEmail);

            var subject = "Your password reset code";

            var html = $@"
        <h2>Password Reset</h2>
        <p>Your reset code is:</p>
        <h1 style='letter-spacing:4px'>{code}</h1>
        <p>This code expires in 10 minutes.</p>
    ";

            var msg = MailHelper.CreateSingleEmail(
                from,
                to,
                subject,
                code,
                html
            );

            var response = await client.SendEmailAsync(msg);

            if ((int)response.StatusCode >= 400)
                throw new Exception("SendGrid reset code email failed");
        }
    }
}
