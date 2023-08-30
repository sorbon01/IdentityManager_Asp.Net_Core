using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
	public class AdminWithOver1000DaysHandler : AuthorizationHandler<AdminWithMoreThan1000DaysRequirement>
	{
		readonly INumberOfDaysForAccount numberOfDaysForAccount;
		public AdminWithOver1000DaysHandler(INumberOfDaysForAccount numberOfDaysForAccount)
		{
			this.numberOfDaysForAccount = numberOfDaysForAccount;
		}

		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminWithMoreThan1000DaysRequirement requirement)
		{
			if (!context.User.IsInRole("Admin"))
			{
				return Task.CompletedTask;
			}
			
			var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
			var numberOfDays = numberOfDaysForAccount.Get(userId);
			if(numberOfDays>=requirement.Days)
			{
				context.Succeed(requirement);
			}
			return Task.CompletedTask;
		}

	}
}
