using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RealCordinator.Api.Controllers
{
    [ApiController]
    [Route("api/profile")]
    [Authorize] // 🔐 THIS PROTECTS THE API
    public class ProfileController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetProfile()
        {
            return Ok(new
            {
                message = "This is a protected profile API",
                email = User.Identity?.Name
            });
        }
    }
}
