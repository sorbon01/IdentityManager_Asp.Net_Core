using IdentityManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace IdentityManager.Controllers
{
	public class RoleController : Controller
	{
		readonly ApplicationDbContext _db;
		readonly UserManager<IdentityUser> _userManager;
		readonly RoleManager<IdentityRole> _roleManager;
		public RoleController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
		{
			_db = db;
			_userManager = userManager;
			_roleManager = roleManager;
		}

		[HttpGet]
		public IActionResult Index()
		{
			var roles = _db.Roles.ToList();
			return View(roles);
		}

		[HttpGet]
		public IActionResult Upsert(string id)
		{
			if (string.IsNullOrWhiteSpace(id))
			{
				return View(new IdentityRole { Id = " "});
			}
			else
			{
				//update
				var objFromDb = _db.Roles.FirstOrDefault(x => x.Id == id);
				return View(objFromDb);
			}

		}

		[HttpPost]
		[Authorize(Policy = "OnlySuperAdminChecker")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Upsert(IdentityRole roleObj)
		{
			if( await _roleManager.RoleExistsAsync(roleObj.Name))
			{
				//error
				TempData[SD.Error] = "Role already exists.";
				return RedirectToAction(nameof(Index));
			}
			if (string.IsNullOrWhiteSpace(roleObj.Id))
			{
				//create
				await _roleManager.CreateAsync(new IdentityRole { Name = roleObj.Name });
				TempData[SD.Success] = "Role created successfully";
			}
			else
			{
				//update
				var objFromDb = _db.Roles.FirstOrDefault(x => x.Id == roleObj.Id);
				if(objFromDb == null)
				{
					TempData[SD.Error] = "Role not found.";
					return RedirectToAction(nameof(Index));
				}
				objFromDb.Name = roleObj.Name;
				objFromDb.NormalizedName = roleObj.Name.ToUpper();
				var result = await _roleManager.UpdateAsync(objFromDb);
				TempData[SD.Success] = "Role updated successfully";
			}
			return RedirectToAction(nameof(Index));

		}

		[HttpPost]
		[Authorize(Policy = "OnlySuperAdminChecker")]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Delete(string id)
		{
			var objFromDb = _db.Roles.FirstOrDefault(x => x.Id == id);
			if (objFromDb == null)
			{
				TempData[SD.Error] = "Role not found.";
				return RedirectToAction(nameof(Index));
			}
			var userRoleForThisRole = _db.UserRoles.Where(u => u.RoleId == id).Count();
			if(userRoleForThisRole > 0)
			{
				TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
				return RedirectToAction(nameof(Index));
			}
			await _roleManager.DeleteAsync(objFromDb);
			TempData[SD.Success] = "Role deleted successfully";
			return RedirectToAction(nameof(Index));
		}
	}
}
