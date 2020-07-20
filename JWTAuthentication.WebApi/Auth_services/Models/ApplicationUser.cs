using System.Collections.Generic;
using Auth.Auth_services.Entities;
using Microsoft.AspNetCore.Identity;

namespace Auth.Auth_services.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}
