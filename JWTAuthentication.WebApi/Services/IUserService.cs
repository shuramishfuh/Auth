﻿using JWTAuthentication.WebApi.Models;
using System.Threading.Tasks;

namespace JWTAuthentication.WebApi.Services
{
    public interface IUserService
    {
        Task<string> RegisterAsync(RegisterModel model);
        Task<string> DeleteUserAsync(RegisterModel model);
        Task<string>UpdateUserEmailAsync(string currentEmail, string newEmail);
        Task<AuthenticationModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
        Task<string> RemoveRoleAsync(AddRoleModel model);
        Task<string> UpdateUserAsync(RegisterModel model);
        Task<string> ConfirmEmailAsync(string userId, string token);
        Task<string> SendEmail(string emailTo, string subject, string body);
        Task<AuthenticationModel> RefreshTokenAsync(string jwtToken);

        bool RevokeToken(string token);
        ApplicationUser GetById(string id);
    }
}
