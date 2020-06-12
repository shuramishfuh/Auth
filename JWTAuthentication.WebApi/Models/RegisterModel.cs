using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.WebApi.Models
{
    public class RegisterModel
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        public string Email { get; set; }
        [Required][MinLength(6)]
        public string Password { get; set; }
    }
}
