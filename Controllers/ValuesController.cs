using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AUTH_JWT.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ValuesController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new { message = "This is a protected endpoint", user = User.Identity?.Name });
    }

    [AllowAnonymous]
    [HttpGet("public")]
    public IActionResult GetPublic()
    {
        return Ok(new { message = "This is a public endpoint" });
    }
}
