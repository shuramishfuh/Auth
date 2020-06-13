using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.WebApi.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        [HttpGet]
#pragma warning disable 1998
        public async Task<IActionResult> GetSecuredData()
#pragma warning restore 1998
        {
            return Ok("This Secured Data is available only for Authenticated Users.");
        }
        [HttpPost]
        [Authorize(Roles ="Administrator")]
#pragma warning disable 1998
        public async Task<IActionResult> PostSecuredData()
#pragma warning restore 1998
        {
            return Ok("This Secured Data is available only for Administrators.");
        }
    }
}