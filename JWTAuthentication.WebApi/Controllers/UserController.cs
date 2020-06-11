using System;
using System.Threading.Tasks;
using JWTAuthentication.WebApi.Models;
using JWTAuthentication.WebApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }
        /// <summary>
        /// register new user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        
        [HttpPost("register")]
        public async Task<ActionResult> RegisterAsync([FromBody]RegisterModel model)
        {

            var result = await _userService.RegisterAsync(model);
            return Ok(result);
        }

        /// <summary>
        /// gets token or generates new 
        /// </summary>
        /// <param name="model"> email password</param>
        /// <returns></returns>
        [HttpPost("token")]
        public async Task<ActionResult> GetTokenAsync([FromBody]TokenRequestModel model)
        {
            var result = await _userService.GetTokenAsync(model);
            SetRefreshTokenInCookie(result.RefreshToken);
            return Ok(result);
        }
        /// <summary>
        /// adds roles to user with current roles
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("addrole")]
        public async Task<ActionResult> AddRoleAsync(AddRoleModel model)
        {
            var result = await _userService.AddRoleAsync(model);
            return Ok(result);
        }

        /// <summary>
        /// refresh existing token 
        /// </summary>
        /// <returns></returns>
        [HttpPost("refresh-token")]
        public async Task<ActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = await _userService.RefreshTokenAsync(refreshToken);
            if (!string.IsNullOrEmpty(response.RefreshToken))
                SetRefreshTokenInCookie(response.RefreshToken);
            return Ok(response);
        }
        
        /// <summary>
        ///  revoke token and render it inactive
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("revoke-token")]
        public async Task<ActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = _userService.RevokeToken(token);

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }
        private void SetRefreshTokenInCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(10),
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        [Authorize]
        [HttpPost("tokens/{id}")]
        public ActionResult GetRefreshTokens(string id)
        {
            var user = _userService.GetById(id);
            return Ok(user.RefreshTokens);
        }

       
    }
}