using System.ComponentModel.DataAnnotations;

namespace Auth.Auth_services.Models
{
    public class RegisterModel
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Username { get; set; }
        [Required][EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
