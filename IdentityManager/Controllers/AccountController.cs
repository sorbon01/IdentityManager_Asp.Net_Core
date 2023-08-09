using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender; 

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register( string returnUrl = null)
        {
			ViewData["ReturnUrl"] = returnUrl;
			RegisterViewModel registerViewModel = new RegisterViewModel();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
			ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
			if (ModelState.IsValid)
            {
                var user= new ApplicationUser { UserName = model.Email,Email=model.Email, Name=model.Name};
                var result  = await _userManager.CreateAsync(user,model.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
                AddErrors(result);
            }
            return View(model);
        }

		[HttpGet]
		public IActionResult Login(string returnUrl = null)
		{
            ViewData["ReturnUrl"] = returnUrl;
			return View();
		}

		[HttpPost]
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
                    return LocalRedirect(returnUrl);
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
		public IActionResult ForgotPassword()
		{
			return View();
		}

		[HttpPost]
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
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

		[HttpGet]
		public IActionResult ResetPassword(string code = null)
		{
			return code==null?View("Error"):View();
		}

		[HttpPost]
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
		public IActionResult ResetPasswordConfirmation()
		{
			return View();
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
