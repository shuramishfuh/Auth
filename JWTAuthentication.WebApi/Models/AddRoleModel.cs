using System.ComponentModel.DataAnnotations;
using JWTAuthentication.WebApi.Constants;

namespace JWTAuthentication.WebApi.Models
{
    public class AddRoleModel
    {
        [Required][EmailAddress]
        public string Email { get; set; }
        [Required][MinLength(6)]
        public string Password { get; set; }
        [Required][EnumDataType(typeof(Authorization.Roles))]
        public string Role { get; set; }
    }
}
