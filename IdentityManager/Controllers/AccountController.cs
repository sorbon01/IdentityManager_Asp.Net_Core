using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        readonly UserManager<IdentityUser> _userManager;
        readonly SignInManager<IdentityUser> _signInManager;
        readonly IEmailSender _emailSender;
        readonly UrlEncoder _urlEncoder;
        readonly RoleManager<IdentityRole> _roleManager;
        readonly ApplicationDbContext _db;

        public AccountController(
            UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager, 
            IEmailSender emailSender, UrlEncoder urlEncoder, 
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext db)
        {
            _urlEncoder = urlEncoder;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _roleManager = roleManager;
            _db = db;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Register( string returnUrl = null)
        {
            if(!await _roleManager.RoleExistsAsync("Admin"))
            {
                // create roles
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }
            
            List<SelectListItem> listItems= new List<SelectListItem>();
            listItems.Add(new SelectListItem()
            {
                Value = "Admin",
                Text = "Admin"
            });
            listItems.Add(new SelectListItem()
            {
                Value = "User",
                Text = "User"
            });

			ViewData["ReturnUrl"] = returnUrl;
			RegisterViewModel registerViewModel = new RegisterViewModel()
            {
                RoleList= listItems
            };
            return View(registerViewModel);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
			ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
			if (ModelState.IsValid)
            {
                var user= new ApplicationUser { UserName = model.Email,Email=model.Email, Name=model.Name, DateCreated = DateTime.Now };
                var result  = await _userManager.CreateAsync(user,model.Password);
                if (result.Succeeded)
                {
                    if ( !string.IsNullOrWhiteSpace(model.RoleSelected) && model.RoleSelected == "Admin")
                        await _userManager.AddToRoleAsync(user, "Admin");
                    else
                        await _userManager.AddToRoleAsync(user, "User");

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
					var callbackurl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

					await _emailSender.SendEmailAsync(model.Email, "Confirm your Account -- Identity Manager",
							"Please confirm you account by clicking here: <a href=\"" + callbackurl + "\">link</a>");
					await _signInManager.SignInAsync(user, isPersistent: false);
					//add claim firstName
					await _userManager.AddClaimAsync(user, new Claim("FirstName", user.Name));
					return LocalRedirect(returnUrl);
                }
                AddErrors(result);
            }

            List<SelectListItem> listItems = new List<SelectListItem>();
            listItems.Add(new SelectListItem()
            {
                Value = "Admin",
                Text = "Admin"
            });
            listItems.Add(new SelectListItem()
            {
                Value = "User",
                Text = "User"
            });
            model.RoleList= listItems;
            return View(model);
        }


        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail( string userId, string code)
        {
            if(User== null || code== null)
                return View("Error");

            var user = await _userManager.FindByIdAsync(userId);
            if(user == null) 
                return View("Error");

            var result = await _userManager.ConfirmEmailAsync(user, code);

            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }


		[HttpGet]
        [AllowAnonymous]
		public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
			return View();
		}

		[HttpPost]
        [AllowAnonymous]
		[ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl=null)
		{
			ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,lockoutOnFailure:true);
                if(result.Succeeded)
                {
                    var user = _db.ApplicationUser.FirstOrDefault(u => u.Email.ToLower() == model.Email.ToLower());
                    var claims = await _userManager.GetClaimsAsync(user);
                    var claim = claims.FirstOrDefault(c => c.Type == "FirstName");
                    if (claims.Count > 0 && claim != null )
                        await _userManager.RemoveClaimAsync(user, claim);
                    await _userManager.AddClaimAsync(user, new Claim("FirstName", user.Name));

                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode),new { returnUrl, model.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> LogOff(RegisterViewModel model)
		{
            await _signInManager.SignOutAsync();
			return RedirectToAction(nameof(HomeController.Index),"Home");
		}

		[HttpGet]
        [AllowAnonymous]
		public IActionResult ForgotPassword()
        {
			return View();
		}

		[HttpPost]
        [AllowAnonymous]
		[ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
		{
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Reset Password -- Identity Manager",
                        "Please reset your password by clicking here: <a href=\"" + callbackurl + "\">link</a>");
				return RedirectToAction("ForgotPasswordConfirmation");
			}


			return View(model);
		}

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

		[HttpGet]
        [AllowAnonymous]
		public IActionResult ResetPassword(string code = null)
        {
			return code==null?View("Error"):View();
		}

		[HttpPost]
        [AllowAnonymous]
		[ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);
				if (user == null)
				{
					return RedirectToAction("ResetPasswordConfirmation");
				}

				var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if(result.Succeeded)
				    return RedirectToAction("ForgotPasswordConfirmation");

                AddErrors(result);
			}


			return View();
		}

		[HttpGet]
        [AllowAnonymous]
		public IActionResult ResetPasswordConfirmation()
        {
			return View();
		}

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl=null)
        {
			
			// request a redirect to the external login provider
			var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

		[HttpGet]
        [AllowAnonymous]
		public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
			returnUrl = returnUrl ?? Url.Content("~/");
			if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if(info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            // Sign in the user with this external login provider.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,info.ProviderKey, isPersistent: true);
            if (result.Succeeded)
            {
                //update any authentication tokens
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
				//add claim firstName
				var email = info.Principal.FindFirstValue(ClaimTypes.Email);
				var user = _db.ApplicationUser.FirstOrDefault(u => u.Email.ToLower() == email.ToLower());
				var claims = await _userManager.GetClaimsAsync(user);
				var claim = claims.FirstOrDefault(c => c.Type == "FirstName");
				if (claims.Count > 0 && claim != null)
					await _userManager.RemoveClaimAsync(user, claim);
				await _userManager.AddClaimAsync(user, new Claim("FirstName", user.Name));

				return LocalRedirect(returnUrl); 
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticatorCode", new {returnUrl = returnUrl});
            }
            else
            {
                //If the user does not have account, then we will ask the user to create an account.
                ViewData["ReturnUrl"]= returnUrl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);
				return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email, Name = name });
            }
		}

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
			returnUrl = returnUrl ?? Url.Content("~/");
			if (ModelState.IsValid)
            {
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if (info == null)
				{
					return View("Error");
				}
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name, DateCreated = DateTime.Now };
				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					await _userManager.AddToRoleAsync(user, "User");
					result = await _userManager.AddLoginAsync(user,info);
					if (result.Succeeded)
					{
						await _signInManager.SignInAsync(user, isPersistent: false);
						await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
						return LocalRedirect(returnUrl);
					}
				}
				AddErrors(result);
			}
            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digit=6";

            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthenticatorUri = string.Format(AuthenticatorUriFormat, _urlEncoder.Encode("IdentityManager"),
                                _urlEncoder.Encode(user.Email), token);
            var model = new TwoFactorAuthenticationViewModel() { Token = token, QRCodeUrl = AuthenticatorUri };
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpPost]
		public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
		{
			if(ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
					return RedirectToAction(nameof(AuthenticatorConfirmation));
				}
				ModelState.AddModelError("Verify", "Your two factor auth code could be avalidated.");
			}
			return View(model);
		}
        [HttpGet]
		public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user== null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerifyAuthenticationViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe});
        }



        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticationViewModel model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: false);

            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid Code.");
                return View(model);
            }
        }








        private void AddErrors(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

    }
}
