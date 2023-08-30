using IdentityManager.Authorize;
using IdentityManager.Data;
using IdentityManager.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddIdentity<IdentityUser,IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 5;
    options.Password.RequireLowercase = true;
    options.Lockout.DefaultLockoutTimeSpan= TimeSpan.FromSeconds(30);
    options.Lockout.MaxFailedAccessAttempts = 2;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = new PathString("/Home/AccessDenied");
});

builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = "YourFacebookAppId";
    options.AppSecret = "YourFacebookAppSecret";
});

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    opt.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin").RequireRole("User"));
    opt.AddPolicy("Admin_CreateAccess", policy => policy.RequireRole("Admin").RequireClaim("create","True"));
    opt.AddPolicy("Admin_Create_Edit_DeleteAccess", policy => policy.RequireRole("Admin")
        .RequireClaim("create","True")
        .RequireClaim("edit","True")
        .RequireClaim("Delete","True"));

	opt.AddPolicy("Admin_Create_Edit_DeleteAccess_Or_SuperAdmin", policy => policy.RequireAssertion(context => AuthorizeAdminWithClaimsOrSuperAdmin(context)));
    opt.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
    opt.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
    opt.AddPolicy("FirstNameAuth", policy => policy.Requirements.Add(new FirstNameAuthRequirement("Сорбон")));
});

builder.Services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthorization();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();


bool AuthorizeAdminWithClaimsOrSuperAdmin(AuthorizationHandlerContext context)
{
    return (context.User.IsInRole("Admin") &&
		    context.User.HasClaim(c => c.Type == "Create" && c.Value == "True") &&
		    context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True") &&
		    context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
		    ) || context.User.IsInRole("SuperAdmin"
        );
}
