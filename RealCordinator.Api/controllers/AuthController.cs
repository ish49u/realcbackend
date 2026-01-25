using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RealCordinator.Api.Data;
using RealCordinator.Api.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Google.Apis.Auth;
using RealCordinator.Api.DTOs;
using RealCordinator.Api.Services;

namespace RealCordinator.Api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;
        private readonly EmailService _emailService;

        public AuthController(
            AppDbContext db,
            IConfiguration config,
            ILogger<AuthController> logger,
            EmailService emailService)
        {
            _db = db;
            _config = config;
            _logger = logger;
            _emailService = emailService;
        }
        // ================= REGISTER =================
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            try
            {
                _logger.LogInformation("REGISTER REQUEST: {Email}", request.Email);

                if (string.IsNullOrWhiteSpace(request.Email) ||
                    string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new { error = "Email and password are required" });
                }

                var exists = await _db.Users.AnyAsync(u => u.Email == request.Email);
                if (exists)
                {
                    return BadRequest(new { error = "Email already registered" });
                }

                var hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);

                var verificationToken = Guid.NewGuid().ToString();

                var user = new User
                {
                    Email = request.Email,
                    PasswordHash = hashedPassword,
                    IsEmailVerified = false,
                    EmailVerificationToken = verificationToken,
                    EmailVerificationExpiry = DateTime.UtcNow.AddHours(24)
                };

                _db.Users.Add(user);
                await _db.SaveChangesAsync();

                // SEND VERIFICATION EMAIL
                var verifyLink =
                    $"{Request.Scheme}://{Request.Host}/api/auth/verify-email?token={verificationToken}";

                await _emailService.SendVerificationEmail(
                    user.Email,
                    verifyLink
                );

                _logger.LogInformation("USER REGISTERED (UNVERIFIED): {Email}", request.Email);

                return Ok(new
                {
                    message = "Verification email sent"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "REGISTER FAILED");

                return StatusCode(500, new
                {
                    error = "Register failed",
                    details = ex.Message
                });
            }
        }

        // ================= LOGIN =================
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                _logger.LogInformation("LOGIN REQUEST: {Email}", request.Email);

                if (string.IsNullOrWhiteSpace(request.Email) ||
                    string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new { error = "Email and password are required" });
                }

                var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
                if (user == null)
                {
                    return Unauthorized(new { error = "Invalid credentials" });
                }

                var validPassword = BCrypt.Net.BCrypt.Verify(
                    request.Password,
                    user.PasswordHash
                );

                if (!user.IsEmailVerified)
                {
                    return Unauthorized(new
                    {
                        error = "Please verify your email before logging in"
                    });
                }

                var token = GenerateJwtToken(user);

                return Ok(new
                {
                    message = "Login successful",
                    token
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LOGIN FAILED");

                return StatusCode(500, new
                {
                    error = "Login failed",
                    details = ex.Message
                });
            }
        }


        [HttpGet("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u =>
                u.EmailVerificationToken == token &&
                u.EmailVerificationExpiry > DateTime.UtcNow
            );

            if (user == null)
                return BadRequest("Invalid or expired verification link");

            user.IsEmailVerified = true;
            user.EmailVerificationToken = null;
            user.EmailVerificationExpiry = null;

            await _db.SaveChangesAsync();

            return Ok("Email verified successfully. You can now log in.");
        }


        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.IdToken))
                {
                    return BadRequest(new { error = "Google token is required" });
                }

                // ✅ Verify token with Google
                var payload = await GoogleJsonWebSignature.ValidateAsync(
                    request.IdToken,
                    new GoogleJsonWebSignature.ValidationSettings
                    {
                        Audience = new[]
                        {
                    _config["GoogleAuth:ClientId"] // WEB CLIENT ID
                        }
                    });

                // 🔍 Find user
                var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == payload.Email);

                // 🆕 Create user if not exists
                if (user == null)
                {
                    user = new User
                    {
                        Email = payload.Email,
                        PasswordHash = "GOOGLE_AUTH",
                        IsEmailVerified = true
                    };


                    _db.Users.Add(user);
                    await _db.SaveChangesAsync();
                }

                var token = GenerateJwtToken(user);

                return Ok(new
                {
                    message = "Google login successful",
                    token
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GOOGLE LOGIN FAILED");

                return Unauthorized(new
                {
                    error = "Invalid Google token",
                    details = ex.Message
                });
            }
        }


        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Email))
                return BadRequest(new { error = "Email is required" });

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
                return Ok(new { message = "If email exists, code sent" });

            var code = new Random().Next(100000, 999999).ToString();

            user.PasswordResetCode = code;
            user.PasswordResetExpiry = DateTime.UtcNow.AddMinutes(10);

            await _db.SaveChangesAsync();

            await _emailService.SendResetCodeEmail(user.Email, code);

            return Ok(new { message = "Reset code sent" });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Code) ||
                string.IsNullOrWhiteSpace(request.NewPassword))
            {
                return BadRequest(new { error = "Code and password required" });
            }

            var user = await _db.Users.FirstOrDefaultAsync(u =>
                u.PasswordResetCode == request.Code &&
                u.PasswordResetExpiry > DateTime.UtcNow
            );

            if (user == null)
                return BadRequest(new { error = "Invalid or expired code" });

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
            user.PasswordResetCode = null;
            user.PasswordResetExpiry = null;

            await _db.SaveChangesAsync();

            return Ok(new { message = "Password reset successful" });
        }

        // ================= JWT TOKEN =================
        private string GenerateJwtToken(User user)
        {
            var jwt = _config.GetSection("Jwt");

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwt["Key"]!)
            );

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: jwt["Issuer"],
                audience: jwt["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    int.Parse(jwt["ExpireMinutes"]!)
                ),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
