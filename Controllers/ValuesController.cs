using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AUTH_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        [HttpGet]
        [Authorize]
        public IActionResult Get()
        {
            return Ok(new { message = "This is a protected endpoint" });
        }

        [HttpGet("public")]
        public IActionResult GetPublic()
        {
            return Ok(new { message = "This is a public endpoint" });
        }
    }
}
