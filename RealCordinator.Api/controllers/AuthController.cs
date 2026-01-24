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

namespace RealCordinator.Api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            AppDbContext db,
            IConfiguration config,
            ILogger<AuthController> logger)
        {
            _db = db;
            _config = config;
            _logger = logger;
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

                var user = new User
                {
                    Email = request.Email,
                    PasswordHash = hashedPassword
                };

                _db.Users.Add(user);
                await _db.SaveChangesAsync();

                _logger.LogInformation("USER REGISTERED: {Email}", request.Email);

                return Ok(new
                {
                    message = "User registered successfully"
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

                if (!validPassword)
                {
                    return Unauthorized(new { error = "Invalid credentials" });
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
                        PasswordHash = "GOOGLE_AUTH"
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
