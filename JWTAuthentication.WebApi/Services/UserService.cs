using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JWTAuthentication.WebApi.Constants;
using JWTAuthentication.WebApi.Contexts;
using JWTAuthentication.WebApi.Entities;
using JWTAuthentication.WebApi.Models;
using JWTAuthentication.WebApi.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.WebApi.Services.Auth
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JWT _jwt;

        public UserService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
            _userManager = userManager;
            _jwt = jwt.Value;
        }

        public async Task<string> RegisterAsync(RegisterModel model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };
            var userWithSameEmail = await _userManager.FindByEmailAsync(model.Email);
            if (userWithSameEmail != null) return $"Email {user.Email} is already registered.";
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) return $"Error occured check your credentials {user}";
            await _userManager.AddToRoleAsync(user, Authorization.DefaultRole.ToString());
            await _context.SaveChangesAsync();
            var getUser = await _userManager.FindByEmailAsync(model.Email);
            var confirmEmailToken = await _userManager.GenerateEmailConfirmationTokenAsync(getUser);
            var encodeEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);
            var validEmailToken = WebEncoders.Base64UrlEncode(encodeEmailToken);
            var url = $"{_configuration["AppUrl"]}/api/user/confirmEmail?userid={getUser.Id}&token={validEmailToken}"; // change AppUrl in config after deployment
            await SendEmail(getUser.Email, "Confirm your email", $"<h1>Welcome</h1>" +
                                                                 $"<p>Please confirm your email by <a href='{url}'>Clicking here</a></p>");


            return $"Success User Registered with username {user.UserName}";
        }

        /// <summary>
        /// updates users
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public async Task<string> UpdateUserAsync(RegisterModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null)
            {
                return $"No user with {model.Email }  found.";
            }

            if (model.Username != null)
                user.UserName = model.Username;
            if (model.FirstName != null)
                user.FirstName = model.FirstName;
            if (model.LastName != null)
                user.LastName = model.LastName;


            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) return $"Error occured could not update user {user}";
            await _context.SaveChangesAsync();
            return $"Success User updated";

        }

        public async Task<string> DeleteUserAsync(RegisterModel model)
        {
            var userWithSameEmail = await _userManager.FindByEmailAsync(model.Email);
            if (userWithSameEmail == null) return $" No User with Email {model.Email} was found.";
            var result = await _userManager.DeleteAsync(userWithSameEmail);
            if (!result.Succeeded) return $"Error occured could not delete user with email{model.Email} ";
            // await _userManager.AddToRoleAsync(user, Authorization.DefaultRole.ToString());
            await _context.SaveChangesAsync();
            return $"Success user was deleted";
        }

        public async Task<AuthenticationModel> GetTokenAsync(TokenRequestModel model)
        {
            var authenticationModel = new AuthenticationModel();
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"No Accounts Registered with {model.Email}.";
                return authenticationModel;
            }
            if (await _userManager.CheckPasswordAsync(user, model.Password))
            {
                if (user.EmailConfirmed)
                {
                    authenticationModel.IsAuthenticated = true;
                    var jwtSecurityToken = await CreateJwtToken(user);
                    authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
                    authenticationModel.Email = user.Email;
                    authenticationModel.UserName = user.UserName;
                    var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
                    authenticationModel.Roles = rolesList.ToList();


                    if (user.RefreshTokens.Any(a => a.IsActive))
                    {
                        var activeRefreshToken = user.RefreshTokens.FirstOrDefault(a => a.IsActive);
                        if (activeRefreshToken == null) return authenticationModel;
                        authenticationModel.RefreshToken = activeRefreshToken.Token;
                        authenticationModel.RefreshTokenExpiration = activeRefreshToken.Expires;
                    }
                    else
                    {
                        var refreshToken = CreateRefreshToken();
                        authenticationModel.RefreshToken = refreshToken.Token;
                        authenticationModel.RefreshTokenExpiration = refreshToken.Expires;
                        user.RefreshTokens.Add(refreshToken);
                        _context.Update(user);
                        await _context.SaveChangesAsync();
                    }

                    return authenticationModel;
                }
                authenticationModel.Message = $"Email {user.Email} not verified .";
                return authenticationModel;
            }
            authenticationModel.IsAuthenticated = false;
            authenticationModel.Message = $"Incorrect Credentials for user {user.Email}.";
            return authenticationModel;
        }

        private static RefreshToken CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(randomNumber);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow
            };
        }

        /// <summary>
        /// creates now token for new user 
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = roles.Select(t => new Claim("roles", t)).ToList();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }

        /// <summary>
        /// adds to  a user
        /// </summary>
        /// <param name="model"> email, password role</param>
        /// <returns></returns>
        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return $"No Accounts Registered with {model.Email}.";
            }

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
                return $"Incorrect Credentials for user {user.Email}.";
            var roleExists = Enum.GetNames(typeof(Authorization.Roles)).Any(x => x.ToLower() == model.Role.ToLower());
            if (!roleExists) return $"Role {model.Role} not found.";
            {
                var validRole = Enum.GetValues(typeof(Authorization.Roles)).Cast<Authorization.Roles>().FirstOrDefault(x => x.ToString().ToLower() == model.Role.ToLower());
                await _userManager.AddToRoleAsync(user, validRole.ToString());
                await _context.SaveChangesAsync();
                return $"Success {model.Role} to user {model.Email}.";
            }

        }


        public async Task<string> RemoveRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return $"No Accounts Registered with {model.Email}.";
            }

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
                return $"Incorrect Credentials for user {user.Email}.";
            var roleExists = Enum.GetNames(typeof(Authorization.Roles)).Any(x => x.ToLower() == model.Role.ToLower());
            if (!roleExists) return $"Role {model.Role} not found.";
            {
                var validRole = Enum.GetValues(typeof(Authorization.Roles)).Cast<Authorization.Roles>().FirstOrDefault(x => x.ToString().ToLower() == model.Role.ToLower());
                await _userManager.RemoveFromRoleAsync(user, validRole.ToString());
                await _context.SaveChangesAsync();
                return $"Success {model.Role} role was removed from user {model.Email}.";
            }

        }

        /// <summary>
        /// refresh token checking for refresh token then renews 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public async Task<AuthenticationModel> RefreshTokenAsync(string token)
        {
            var authenticationModel = new AuthenticationModel();
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"Token did not match any users.";
                return authenticationModel;
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"Token Not Active.";
                return authenticationModel;
            }

            //Revoke Current Refresh Token
            refreshToken.Revoked = DateTime.UtcNow;

            //Generate new Refresh Token and save to Database
            var newRefreshToken = CreateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            _context.Update(user);
            _context.SaveChanges();

            //Generates new jwt
            authenticationModel.IsAuthenticated = true;
            JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
            authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authenticationModel.Email = user.Email;
            authenticationModel.UserName = user.UserName;
            var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            authenticationModel.Roles = rolesList.ToList();
            authenticationModel.RefreshToken = newRefreshToken.Token;
            authenticationModel.RefreshTokenExpiration = newRefreshToken.Expires;
            return authenticationModel;
        }


        /// <summary>
        /// revokes existing token
        /// </summary>
        /// <param name="token"> current token</param>
        /// <returns></returns>
        public bool RevokeToken(string token)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            // return false if no user found with token
            if (user == null) return false;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // return false if token is not active
            if (!refreshToken.IsActive) return false;

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            _context.Update(user);
            _context.SaveChanges();

            return true;
        }

        /// <summary>
        /// get user by id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public ApplicationUser GetById(string id)
        {
            return _context.Users.Find(id);
        }

        /// <summary>
        /// send email
        /// </summary>
        /// <param name="emailTo"></param>
        /// <param name="subject"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public async Task<string> SendEmail(string emailTo, string subject, string body)
        {
            var from = _configuration.GetValue<string>("Email:address");
            var password = _configuration.GetValue<string>("Email:password");
            var message = new MailMessage(from, emailTo, subject, body)
            {
                IsBodyHtml = true,
                BodyEncoding = Encoding.UTF8,
                SubjectEncoding = Encoding.UTF8
            };
            var smtpClient = new SmtpClient
            {
                Host = _configuration.GetValue<string>("Email:host"),
                Port = _configuration.GetValue<int>("Email:port"),
                EnableSsl = true,
                UseDefaultCredentials = false,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Credentials = new System.Net.NetworkCredential(@from, password)
            };


            await smtpClient.SendMailAsync(message);

            return "Successful";
        }

        /// <summary>
        /// verify email
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public async Task<string> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            { return $"Error User not found"; }

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            var normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ConfirmEmailAsync(user, normalToken);

            return result.Succeeded ? $"Success Email confirmed" : $"Error Could not confirm email";
        }


        public async Task<string> ForgetPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return $"Error User not found";

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Encoding.UTF8.GetBytes(token);
            var validToken = WebEncoders.Base64UrlEncode(encodedToken);

            var url = $"{_configuration["AppUrl"]}/ResetPassword?email={email}&token={validToken}";

            await SendEmail(email, "Reset Password", "<h1> Reset your password</h1>" +
                                                                       $"<p>To reset your password <a href='{url}'>Click here</a></p>");

            return "Success Reset password URL has been sent to the email successfully";

        }



        public async Task<string> ResetPasswordAsync(PasswordResetViewModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return "user not found";


            if (model.NewPassword != model.ConfirmPassword)
                return "Password doesn't match its confirmation";

            var decodedToken = WebEncoders.Base64UrlDecode(model.Token);
            var normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ResetPasswordAsync(user, normalToken, model.NewPassword);

            return result.Succeeded ? "Success Password has been reset" : "Error Something went wrong";
        }

    }
}
