In today's world, where web applications are becoming increasingly popular and widely used, security has become a primary concern for web developers. One of the essential aspects of secure web application development is user authentication and authorization. JSON Web Tokens (JWT) is a popular method for implementing authentication and authorization in web applications.

JWT is a JSON-based open standard for creating secure and compact tokens that can be used to securely transmit information between parties. The tokens are designed to be self-contained, meaning that all the necessary information required for authentication and authorization is embedded in the token itself.

By using JWTs, developers can ensure that their web applications are secure, as the tokens are digitally signed and can be verified by the server to ensure that the data has not been tampered with. Moreover, JWTs are highly efficient and can be used in a variety of scenarios, including single sign-on (SSO) authentication, authorization, and more.

This article will provide a comprehensive understanding of JWTs and how they can be used in web applications to provide secure and efficient authentication and authorization. I will discuss how JWTs work, the components of a JWT, how to generate and use JWTs in web applications, and best practices for JWT security. By the end of this article, you will have a solid understanding of JWTs and their benefits, as well as how to implement them in your own web applications for secure authentication and authorization.

We will be using a weather forecast API that comes with ASP.NET Core 7. We will create an ASP.NET Core web application that will interact with the API using Razor pages and JWT for authentication and authorization. Our web application will use JWT to authenticate users and provide them with access to the weather forecast data. By the end of this tutorial, you will have a working web application that demonstrates the use of JWT for secure authentication and authorization, as well as how to interact with an API using ASP.NET Core. So let's get started!

- Create a folder
![image.png](/.attachments/image-5ee02f88-af88-43db-bfd9-28e9d835f674.png)

- Open Visual Studio and select ASP.NET Core Web App
![image.png](/.attachments/image-f0cb80d2-2f0a-41e4-99c4-2c377bae434a.png)

- Ensure your path reflects the path of the folder you just made
![image.png](/.attachments/image-6acd6baf-120d-4817-b9d3-5f1ba8e71f83.png)

- Next, you want to add Individual Accounts
![image.png](/.attachments/image-27fdfe79-3030-441d-80b5-042fe3cc5a6f.png)

- You will need a few packages to begin. Go to packages and then manage Nuget packages
![image.png](/.attachments/image-e3daad0d-2d3a-4285-a7b1-67322131b0c9.png) 

- Install JwtBearer 
![image.png](/.attachments/image-34a3d8ba-1dde-4e6c-9135-bec42447b6c9.png)

- Install tokens.jwt
![image.png](/.attachments/image-9f5b800b-331a-47d6-a34d-68d47451720a.png)

- Go to the areas folder and delete the identity file
![image.png](/.attachments/image-4889f7a5-bd80-4eed-9f76-11ce0ff28fa4.png)

- Once deleted, right-click the Areas folder > Add > Add New Scaffolded Item
You are going to want to select Identity
![image.png](/.attachments/image-c51116b0-6c64-4582-91ff-cec6c7bc4030.png)

- Once the Add Identity Box appears, check the following boxes
![image.png](/.attachments/image-ab8559c0-1e09-4c65-8d98-80217ba039ea.png)

- In that same add Identity popup, you must click the drop-down for the Data context class and select ApplicationDbContext![image.png](/.attachments/image-d73ca2c9-6b1b-41eb-a8fe-b8747a1fbcde.png)

- Select the Login page
![image.png](/.attachments/image-c2123c4d-f4a3-4d1d-9563-f0c7734ba641.png)

- The login page model is going to be what generates the JSON Web Tokens. What this does is allow all users who log in to have a JSON Web Token. 

  Change your login class to look like this: (note, your namespaces may be different)
```
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Demo.Web.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public LoginModel(SignInManager<IdentityUser> signInManager,ILogger<LoginModel> logger,UserManager<IdentityUser> userManager,IConfiguration configuration)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
            _configuration = configuration;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string ErrorMessage { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");

                    var user = await _userManager.FindByEmailAsync(Input.Email);

                    var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                    var token = new JwtSecurityToken(
                        issuer: _configuration["Jwt:Issuer"],
                        audience: _configuration["Jwt:Audience"],
                        claims: claims,
                        expires: DateTime.Now.AddMinutes(30),
                        signingCredentials: creds
                    );

                    var tokenHandler = new JwtSecurityTokenHandler();
                    var jwt = tokenHandler.WriteToken(token);

                    Response.Cookies.Append("access_token", jwt, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        Expires = DateTime.Now.AddMinutes(30)
                    });

                    return RedirectToPage("/Index", new { jwt });
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}

```
- Next, navigate to Index.cshtml.cs
![image.png](/.attachments/image-4db77af9-1731-472d-a6c3-2043084533a4.png)

- Paste the following code into index model
```
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace Demo.Web.Pages
{
    public class IndexModel : PageModel
    {
        public string Jwt { get; set; }

        private readonly HttpClient _httpClient;

        public IndexModel(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task OnGetAsync()
        {
            Jwt = Request.Cookies["access_token"];
        }
    }
}
```

- Now go to the index.html page
![image.png](/.attachments/image-8e7e3eb2-f099-409b-b60f-47b61fdd392c.png)

- Then paste the following code
```
@page
@model Demo.Web.Pages.IndexModel
@{
}

<!DOCTYPE html>
<html>
<head>
    <title>Index</title>
</head>
<body>
    <h1>Welcome to the Index page</h1>

    @if (!string.IsNullOrEmpty(Model.Jwt))
    {
        <p>Your JWT is @Model.Jwt</p>
    }
    else
    {
        <p>No JWT found.</p>
    }
</body>
</html>
```
- Change the AppSettings.json file so that it looks something like the following: (Note, you should use your own Key)
```
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=aspnet-JWTLab-53bc9b9d-9d6a-45d4-8429-2a2761773502;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Jwt": {
    "Issuer": "your_issuer",
    "Audience": "your_audience",
    "Key": "eyJhbGciOiJIUzI1NiJ9.ew0KICAic3ViIjogIjEyMzQ1Njc4OTAiLA0KICAibmFtZSI6ICJBbmlzaCBOYXRoIiwNCiAgImlhdCI6IDE1MTYyMzkwMjINCn0.6oxf-kcklwkRWneyW2KTI4exTbJUPvikbPAc1OJ_5No"
  }
}
```

- To generate your own key, go here [https://8gwifi.org/jwsgen.jsp]()
![image.png](/.attachments/image-3b9b402c-50ff-4579-a3d6-13efeacbb014.png)

  In this tutorial, we will be using HS256 and your secret that goes in JSON is "Shared Secret"

- As a troubleshooting step, if you would like to confirm that everything is working you can use a token validator here [https://jwt.io/]() 
![image.png](/.attachments/image-2ea66053-265a-4085-a01e-3b301c101486.png)
  Above is an example of a valid Json web token. You can tell because it states signature verified. What I did to test if my generated shared secret was valid is place it in the bottom right section under verify signature. I then pasted the string of characters that was labeled as "Serialize" under the encoded section. What you will notice is that the payload data and header sections reflect what the other website said. This means it worked!

- Here is an example of an invalid signature
![image.png](/.attachments/image-aa15f783-46bb-4003-a77b-66c68c239b96.png)

- Lastly, before starting the application, change your program.cs file so that it reflects the following code:
```
using Demo.Web.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<ApplicationDbContext>();

// Configure JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "your-issuer",
        ValidAudience = "your-audience",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-secret-key"))
    };
});

builder.Services.AddHttpClient();
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
```

- Start the application
![image.png](/.attachments/image-ebdc6c07-3697-4ee9-a84a-8d86566603ac.png)

- Your page should look like this
![image.png](/.attachments/image-b8c506bc-c825-4c7e-b8c2-d6edc0b01eec.png)

  Notice how the page states no JWT found. What I want you to do is test what you have done so far by registering an account and logging in.

- A long string of characters appears! That string is your JSON Web Token for the user account you just made!
![image.png](/.attachments/image-48d09000-6540-494a-b7ee-a2805622c4af.png)

- You are halfway done. Now we must set up the web API so that it can work with the Razor pages project. However, before we get ahead of ourselves. Let's finish the Razor pages Web App so that we no longer have to worry about it.

- Create a folder called models and create a class called "WeatherForecast"
![image.png](/.attachments/image-dfbe04d2-9770-4061-8d7c-215eb32699bf.png)

- Place this code in your WeatherForecast class
```
namespace Demo.Web.Model
{
    public class WeatherForecast
    {
        public DateOnly? Date { get; set; }
        public int? TemperatureC { get; set; }
        public int? TemperatureF => 32 + (int)(TemperatureC / 0.5556);
        public string? Summary
        {
            get; set;
        }
    }
}
```
- Now that we have the WeatherForecast class we can use that as a data transfer object when working with our web API. I would like for you to go to your IndexModel and paste the following code
```
using Demo.Web.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace Demo.Web.Pages
{
    public class IndexModel : PageModel
    {
        public string Jwt { get; set; }

        private readonly HttpClient _httpClient;

        public IndexModel(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public IEnumerable<WeatherForecast> WeatherForecasts { get; set; }

        public async Task OnGetAsync()
        {
            Jwt = Request.Cookies["access_token"];
            WeatherForecasts = await GetWeatherForecastsAsync();
        }

        public async Task<IEnumerable<WeatherForecast>> GetWeatherForecastsAsync()
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7040/WeatherForecast");

                // Add JWT token to the HTTP request header
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Jwt);

                HttpResponseMessage response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    string responseContent = await response.Content.ReadAsStringAsync();
                    IEnumerable<WeatherForecast> weatherForecasts = JsonConvert.DeserializeObject<IEnumerable<WeatherForecast>>(responseContent);
                    return weatherForecasts;
                }
                else
                {
                    // Return "Credentials invalid" if the API request failed with a 401 Unauthorized status code
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return new List<WeatherForecast>();
                    }
                    else
                    {
                        throw new Exception($"API request failed with status code {response.StatusCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"API request failed: {ex.Message}", ex);
            }
        }


    }
}
```
- Next, go to the Index HTML and paste this code:
```
@page
@model IndexModel
@{
    ViewData["Title"] = "Home page";
}

<!DOCTYPE html>
<html>
<head>
    <title>Index</title>
</head>
<body>
    <h1>Welcome to the Index page</h1>
    <form method="get">
        <button type="submit">Get Weather Forecasts</button>
    </form>

    @if (Model.WeatherForecasts != null)
    {
        <table>
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Temperature (C)</th>
                    <th>Temperature (F)</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody>
                @foreach (var weatherForecast in Model.WeatherForecasts)
                {
                    <tr>
                        <td>@weatherForecast.Date</td>
                        <td>@weatherForecast.TemperatureC</td>
                        <td>@weatherForecast.TemperatureF</td>
                        <td>@weatherForecast.Summary</td>
                    </tr>
                }
            </tbody>
        </table>
    }

    @section scripts {
        <script src="~/js/site.js"></script>
    }

    @if (!string.IsNullOrEmpty(Model.Jwt))
    {
        <p>Your JWT is @Model.Jwt</p>
    }
    else
    {
        <p>No JWT found.</p>
    }
</body>
</html>

```

- Then go to program.cs and paste this code:
```
using Demo.Web.Data;
using Demo.Web.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<ApplicationDbContext>();

// Configure JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "your-issuer",
        ValidAudience = "your-audience",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-secret-key"))
    };
});

builder.Services.AddHttpClient();
builder.Services.AddScoped<WeatherForecast>();

builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();

```

- Now that you are all done with the Web App you can move on to the Web API. Right-click on your solution and select add new project.
![image.png](/.attachments/image-1d25c0c2-552f-467f-ac8f-c1a7239f8dde.png)

- Select ASP.NET Core Web API
![image.png](/.attachments/image-9f21f655-3452-4d0c-9c1b-9b6acae9615a.png)

- Name your API
![image.png](/.attachments/image-d95bfcff-d71d-46bf-bbcd-b3747915370c.png)

- Leave the default settings and select create (You may get a docker warning, if so, just click okay for now)
![image.png](/.attachments/image-60163337-e626-4797-94ec-f7d02bcbd479.png)

- You will need a few packages to begin. Go to packages and then manage Nuget packages
![image.png](/.attachments/image-e3daad0d-2d3a-4285-a7b1-67322131b0c9.png) 

- Install JwtBearer 
![image.png](/.attachments/image-34a3d8ba-1dde-4e6c-9135-bec42447b6c9.png)

- Install tokens.jwt
![image.png](/.attachments/image-9f5b800b-331a-47d6-a34d-68d47451720a.png)


- First, go into appsettings.json and change it to contain your key:
```
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Jwt": {
    "Issuer": "your_issuer",
    "Audience": "your_audience",
    "Key": "eyJhbGciOiJIUzI1NiJ9.ew0KICAic3ViIjogIjEyMzQ1Njc4OTAiLA0KICAibmFtZSI6ICJBbmlzaCBOYXRoIiwNCiAgImlhdCI6IDE1MTYyMzkwMjINCn0.6oxf-kcklwkRWneyW2KTI4exTbJUPvikbPAc1OJ_5No"
  }
}
```

- Next, create a class called JWTOptions, this class will come in later
```
namespace Demo.API
{
    public class JwtOptions
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string Key { get; set; }
    }
}
```
- Then, change program.cs to look like the following code:
```
using Demo.API;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var Configuration = builder.Configuration;
// JWT Stuff
builder.Services.Configure<JwtOptions>(Configuration.GetSection("Jwt"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var jwtOptions = Configuration.GetSection("Jwt").Get<JwtOptions>();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
```

- Finally, add the "Authorize" tag to the WeatherForecastController class like this:
```
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Demo.API.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}
```
- To make it easier to run both projects at the same time, right click the solution and select properties
![image.png](/.attachments/image-a9b23ee6-c1ae-45cc-a3b8-22d31dce325e.png)

- You will see a screen like below and will need to change from the option of a single startup project to multiple startup projects and then change the action to "Start"
![image.png](/.attachments/image-b9d28c54-b7a3-4049-ae5f-457da1a8e984.png)

  Once done select apply and okay

- Lastly, before you start, you may have noticed that we placed the port numbers in our code. You could change the code to map to your own ports or change the computer to run on the same port numbers I used.

  if you would like to use the same ports as I did go to the properties folder and change the launch settings.json file in your web API to look like this:

```
{
  "$schema": "https://json.schemastore.org/launchsettings.json",
  "iisSettings": {
    "windowsAuthentication": false,
    "anonymousAuthentication": true,
    "iisExpress": {
      "applicationUrl": "https://localhost:7040",
      "sslPort": 44338
    }
  },
  "profiles": {
    "http": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "launchUrl": "swagger",
      "applicationUrl": "https://localhost:7040",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "https": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "launchUrl": "swagger",
      "applicationUrl": "https://localhost:7040",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "IIS Express": {
      "commandName": "IISExpress",
      "launchBrowser": true,
      "launchUrl": "swagger",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  }
}
```

- next, change your launchsettings.json file in your web app project to look like this:
```
{
  "profiles": {
    "http": {
      "commandName": "Project",
      "launchBrowser": true,
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      },
      "dotnetRunMessages": true,
      "applicationUrl": "http://localhost:5278"
    },
    "https": {
      "commandName": "Project",
      "launchBrowser": true,
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      },
      "dotnetRunMessages": true,
      "applicationUrl": "https://localhost:7209;http://localhost:5278"
    },
    "IIS Express": {
      "commandName": "IISExpress",
      "launchBrowser": true,
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "Docker": {
      "commandName": "Docker",
      "launchBrowser": true,
      "launchUrl": "{Scheme}://{ServiceHost}:{ServicePort}",
      "publishAllPorts": true,
      "useSSL": true
    }
  },
  "iisSettings": {
    "windowsAuthentication": false,
    "anonymousAuthentication": true,
    "iisExpress": {
      "applicationUrl": "http://localhost:61035",
      "sslPort": 44363
    }
  }
}
```
- Select Start
![image.png](/.attachments/image-8eddf567-7f5a-4d34-ad9e-d34bce808ab3.png)

- Provided everything is correct, you will have two websites that launch. Your web API will look like this: 
![image.png](/.attachments/image-6103d747-bf24-43bf-b800-a1369758c138.png)

  And your Web App will look like this: 
  ![image.png](/.attachments/image-83c5b4ad-ec40-4473-b9a8-874fad13e856.png)

  There are many ways to test that it is working and is secure. The most simple way is to open an incognito browser and paste your web application URL into the search bar.
![image.png](/.attachments/image-66afa613-af8e-401c-b8f3-e9cc8352c1e8.png)
When there is no user logged in they do not have a JWT and because they have no JWT they cannot see the weather information.

  The end
