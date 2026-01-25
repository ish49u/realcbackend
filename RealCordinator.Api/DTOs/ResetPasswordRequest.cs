namespace RealCordinator.Api.DTOs
{
    public class ResetPasswordRequest
    {
        public string Code { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}
