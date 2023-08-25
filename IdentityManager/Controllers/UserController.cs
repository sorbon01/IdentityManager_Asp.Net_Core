﻿using IdentityManager.Data;
using IdentityManager.Models;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        readonly ApplicationDbContext _db;
        readonly UserManager<IdentityUser> _userManager;
        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            var userList = _db.ApplicationUser.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            
            foreach(var user in userList)
            {
                var role = userRole.FirstOrDefault(u => u.UserId== user.Id);
                if(role ==null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
                }
            }
            return View(userList);
        }

		public IActionResult Edit(string userId)
		{
            var objFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
			var userRole = _db.UserRoles.ToList();
			var roles = _db.Roles.ToList();
			var role = userRole.FirstOrDefault(u => u.UserId == objFromDb.Id);
            if (role != null)
            {
                objFromDb.RoleId = roles.FirstOrDefault(u=> u.Id == role.RoleId).Id;
            }
            objFromDb.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });

			return View(objFromDb);
		}

        [HttpPost]
        [ValidateAntiForgeryToken]
		public async Task<IActionResult> Edit(ApplicationUser user )
		{
            if(ModelState.IsValid)
            {
				var objFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == user.Id);
				if (objFromDb == null)
				{
					return NotFound();
				}
				var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);
				if (userRole != null)
				{
					var previousRoleName = _db.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
					//removing the old role
					await _userManager.RemoveFromRoleAsync(objFromDb, previousRoleName);
				}

				//add new role
				await _userManager.AddToRoleAsync(objFromDb, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
				objFromDb.Name = user.Name;
				_db.SaveChanges();
				TempData[SD.Success] = "User has been edited successfully.";
                return RedirectToAction(nameof(Index));
			}

			user.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
			{
				Text = u.Name,
				Value = u.Id
			});
			return View(user);
		}


        [HttpPost]
        public IActionResult LockUnlock(string userId)
        {
            var objFromDb = _db.ApplicationUser.FirstOrDefault(u =>u.Id == userId);
            if(objFromDb == null)
            {
                return NotFound();
            }
            if(objFromDb.LockoutEnd!=null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //user is locked will remain locked untill lockuotedn time
                //clicking on this action will unlock them
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully.";
            }
            else
            {
                //user is not locked and we want to lock the user
                objFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked successfully.";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
        }


	}
}
