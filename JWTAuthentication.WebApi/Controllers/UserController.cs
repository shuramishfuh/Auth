using System;
using System.Threading.Tasks;
using JWTAuthentication.WebApi.Filter;
using JWTAuthentication.WebApi.Models;
using JWTAuthentication.WebApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.WebApi.Controllers
{
    [ApikeyAuth]
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
        [HttpPost("Register")]
        public async Task<ActionResult> RegisterAsync([FromBody]RegisterModel model)
        {

            var result = await _userService.RegisterAsync(model);
            if (result.StartsWith("Success"))
            {
                return Ok(result);
            }

            return BadRequest(result);
        } 
        
        
        /// <summary>
        /// Updates existing user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPost("Update")]
        public async Task<ActionResult> UpdateUserAsync([FromBody]RegisterModel model)
        {

            var result = await _userService.UpdateUserAsync(model);
            if (result.StartsWith("Success"))
            {
                return Ok(result);
            }

            return BadRequest(result);
        }
        /// <summary>
        /// delete users 
        /// </summary>
        /// <param name="model">requires user's email address</param>
        /// <returns></returns>
        [Authorize(Roles ="Root")]
        [HttpPost("delete")]
        public async Task<ActionResult> DeleteUserAsync([FromBody] RegisterModel model)
        {
            var result = await _userService.DeleteUserAsync(model);
            if (result.StartsWith("Success"))
            {
                return Ok(result);
            }

            return BadRequest(result);
        }
        /// <summary>
        /// gets token or generates new 
        /// </summary>
        /// <param name="model"> email password</param>
        /// <returns></returns>
        [HttpPost("Token")]
        public async Task<ActionResult> GetTokenAsync([FromBody]TokenRequestModel model)
        {
            var result = await _userService.GetTokenAsync(model);
            if (result.RefreshToken is null)
            {
                return NotFound(result.Message);
            }

            SetRefreshTokenInCookie(result.RefreshToken);
            return Ok(result);

        }
        /// <summary>
        /// adds roles to user with current roles
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Root,Administrator")]
        [HttpPost("AddRole")]
        public async Task<ActionResult> AddRoleAsync(AddRoleModel model)
        {
            var result = await _userService.AddRoleAsync(model);
            if (result.StartsWith("Success"))
            {
                return Ok(result);
            }

            return BadRequest(result);
        }   
        
        /// <summary>
        /// removes roles to user with current roles
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("DeleteRole")]
        [Authorize(Roles = "Root,Administrator")]
        public async Task<ActionResult> RemoveRoleAsync(AddRoleModel model)
        {
            var result = await _userService.RemoveRoleAsync(model);
            if (result.StartsWith("Success"))
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        /// <summary>
        /// refresh existing token 
        /// </summary>
        /// <returns></returns>
        [HttpPost("RefreshToken")]
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
        [HttpPost("RevokeToken")]
        /* method indicates a warning because of
         lack of await in the body 
         if turned async removed cannot convert 
         action result to task 
         so suppresses the warning 
         no effect to code however  */
#pragma warning disable 1998 
        public async Task<ActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
#pragma warning restore 1998
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

        [Authorize, HttpPost("Tokens/{id}")]
        public ActionResult GetRefreshTokens(string id)
        {
            var user = _userService.GetById(id);
            return Ok(user.RefreshTokens);
        }


        // /api/user/confirm-email?userid&token
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
                return NotFound();
            var result = await _userService.ConfirmEmailAsync(userId, token);
            if (result.StartsWith("Success"))
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        // api/user/forget password
        [HttpPost("ForgetPassword")]
        public async Task<IActionResult> ForgetPassword(string email)
        {
            if (string.IsNullOrEmpty(email))
                return NotFound();

            var result = await _userService.ForgetPasswordAsync(email);

            if (result.StartsWith("Success"))
                return Ok(result); 

            return BadRequest(result); 
        }

        // api/user/reset-password
        [HttpPost("ResetPassword")]
        public async Task<ActionResult> ResetPassword([FromForm]PasswordResetViewModel model)
        {
            if (!ModelState.IsValid) return BadRequest("Check your Inputs");
            var result = await _userService.ResetPasswordAsync(model);

            if (result.StartsWith("Success"))
                return Ok(result);

            return BadRequest("error occured Please try again later");

        }  
        
      

    }
}