using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
	[Authorize]
	public class AccessCheckerController : Controller
	{

		[AllowAnonymous]
		//Accessible by everyone, even if users are not logged in.
		public IActionResult AllAccess()
		{
			return View();
		}

		//Accessible by logged in users
		public IActionResult AuthorizedAccess()
		{
			return View();
		}
		[Authorize(Roles ="User")]
		//Accessible by users who have user role
		public IActionResult UserAccess()
		{
			return View();
		}

		[Authorize(Roles = "User,Admin")]
		//Accessible by users who have user or admin role
		public IActionResult UserOrAdminAccess()
		{
			return View();
		}

		[Authorize(Policy =  "UserAndAdmin")]
		//Accessible by users who have user or admin role
		public IActionResult UserAndAdminAccess()
		{
			return View();
		}

		[Authorize(Policy = "Admin")]
		//Accessible by users who have admin role
		public IActionResult AdminAccess()
		{
			return View();

		}
		[Authorize(Policy = "Admin_CreateAccess")]
		//Accessible by users with a claim of create to be True
		public IActionResult Admin_CreateAccess()
		{
			return View();
		}
		[Authorize(Policy = "Admin_Create_Edit_DeleteAccess")]
		//Accessible by Admin user with claim of Create Edit and Delete (AND NOT OR)
		public IActionResult Admin_Create_Edit_DeleteAccess()
		{
			return View();
		}

		[Authorize(Policy = "Admin_Create_Edit_DeleteAccess_Or_SuperAdmin")]
		//Accessible by Admin user with create, edit and delete (AND NOT OR), OR if the user role is superAdmin
		public IActionResult Admin_Create_Edit_DeleteAccess_Or_SuperAdmin()
		{
			return View();
		}

		[Authorize(Policy = "AdminWithMoreThan1000Days")]
		public IActionResult OnlySorbon()
		{
			return View();
		}

		[Authorize(Policy = "FirstNameAuth")]
		public IActionResult FirstNameAuth()
		{
			return View();
		}
	}
}
