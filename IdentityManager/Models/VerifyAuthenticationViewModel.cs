using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class VerifyAuthenticationViewModel
    {
        [Required]
        public string Code { get; set; }
        public string ReturnUrl { get; set; } = null;

        [Display(Name  = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
