using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class TokenRequestModel
    {
        [Required][EmailAddress]
        public string Email { get; set; }
        [Required][MinLength(6)]
        public string Password { get; set; }
    }
}
