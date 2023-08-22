namespace IdentityManager.Models
{
	public class TwoFactorAuthenticationViewModel
	{
		// used to login
		public string Code { get; set; }
		// used to register / sign
		public string Token { get; set; }

		public string QRCodeUrl { get; set; }
	}
}
