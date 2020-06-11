using JWTAuthentication.WebApi.Entities;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace JWTAuthentication.WebApi.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}
