using System.ComponentModel.DataAnnotations;

namespace AUTH_JWT.Models;

public sealed class LoginModel
{
    [Required]
    [StringLength(128, MinimumLength = 1)]
    public string Username { get; set; } = "";

    [Required]
    [StringLength(256, MinimumLength = 1)]
    public string Password { get; set; } = "";
}
