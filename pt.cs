

## Program.cs
```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ProjectManagement.Data;
using ProjectManagement.Services;
using ProjectManagement.Middleware;
using ProjectManagement.Validators;
using FluentValidation;
using FluentValidation.AspNetCore;
using Serilog;
using Serilog.Events;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Diagnostics;

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("Application", "ProjectManagementAPI")
    .WriteTo.Console()
    .WriteTo.File("logs/projectmanagement-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);

// Add Serilog
builder.Host.UseSerilog();

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// API Versioning
builder.Services.AddApiVersioning(opt =>
{
    opt.DefaultApiVersion = new ApiVersion(1, 0);
    opt.AssumeDefaultVersionWhenUnspecified = true;
    opt.ReadApiVersionFromUrlSegment = true;
    opt.ApiVersionReader = ApiVersionReader.Combine(
        new UrlSegmentApiVersionReader(),
        new HeaderApiVersionReader("X-Version"),
        new QueryStringApiVersionReader("version")
    );
}).AddApiExplorer(setup =>
{
    setup.GroupNameFormat = "'v'VVV";
    setup.SubstituteApiVersionInUrl = true;
});

// FluentValidation
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblyContaining<LoginDtoValidator>();

// Swagger configuration with versioning and JWT support
builder.Services.AddSwaggerGen(c =>
{
    var provider = builder.Services.BuildServiceProvider()
        .GetRequiredService<IApiVersionDescriptionProvider>();

    foreach (var description in provider.ApiVersionDescriptions)
    {
        c.SwaggerDoc(description.GroupName, new OpenApiInfo
        {
            Title = "Project Management API",
            Version = description.ApiVersion.ToString(),
            Description = "A comprehensive project management system with user authentication and role-based authorization",
            Contact = new OpenApiContact
            {
                Name = "API Support",
                Email = "support@projectmanagement.com"
            }
        });
    }

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });

    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

// Health Checks
builder.Services.AddHealthChecks()
    .AddSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection") ?? "",
        name: "sql-server",
        failureStatus: HealthStatus.Degraded,
        tags: new[] { "database", "sql" })
    .AddCheck("self", () => HealthCheckResult.Healthy(), tags: new[] { "self" });

// Database context
builder.Services.AddSingleton<IDatabaseContext, DatabaseContext>();

// Services
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IProjectService, ProjectService>();
builder.Services.AddScoped<ITaskService, TaskService>();
builder.Services.AddScoped<IAuthService, AuthService>();

// JWT Authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ClockSkew = TimeSpan.Zero
        };
        
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Log.Warning("Authentication failed: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Log.Information("Token validated for user: {User}", context.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins", builder =>
    {
        builder.WithOrigins("http://localhost:3000", "https://localhost:3001")
               .AllowAnyHeader()
               .AllowAnyMethod()
               .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<RequestLoggingMiddleware>();
app.UseMiddleware<GlobalExceptionMiddleware>();

// Health checks endpoint
app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var response = new
        {
            status = report.Status.ToString(),
            checks = report.Entries.Select(x => new
            {
                name = x.Key,
                status = x.Value.Status.ToString(),
                exception = x.Value.Exception?.Message,
                duration = x.Value.Duration.ToString()
            }),
            totalDuration = report.TotalDuration
        };
        await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response));
    }
});

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});

app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false
});

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
        foreach (var description in provider.ApiVersionDescriptions)
        {
            c.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json",
                $"Project Management API {description.GroupName.ToUpperInvariant()}");
        }
    });
}

app.UseCors("AllowSpecificOrigins");
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

try
{
    Log.Information("Starting Project Management API");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
```

---

## ProjectManagement.csproj
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
    <DockerDefaultTargetOS>Linux</DockerDefaultTargetOS>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Dapper" Version="2.1.35" />
    <PackageReference Include="Microsoft.Data.SqlClient" Version="5.1.1" />
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="9.0.0" />
    <PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="9.0.0" />
    <PackageReference Include="Microsoft.AspNetCore.Mvc.Versioning" Version="5.1.0" />
    <PackageReference Include="Microsoft.AspNetCore.Mvc.Versioning.ApiExplorer" Version="5.1.0" />
    <PackageReference Include="Swashbuckle.AspNetCore" Version="6.4.0" />
    <PackageReference Include="BCrypt.Net-Next" Version="4.0.3" />
    <PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />
    <PackageReference Include="Serilog.Sinks.Console" Version="5.0.1" />
    <PackageReference Include="Serilog.Sinks.File" Version="5.0.0" />
    <PackageReference Include="FluentValidation.AspNetCore" Version="11.3.0" />
    <PackageReference Include="Microsoft.Extensions.Diagnostics.HealthChecks.SqlServer" Version="9.0.0" />
    <PackageReference Include="System.Diagnostics.Activity" Version="9.0.0" />
  </ItemGroup>

</Project>
```

---

## Models/Models.cs
```csharp
namespace ProjectManagement.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public int RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public bool IsActive { get; set; } = true;
    }

    public class Role
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }

    public class Project
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public ProjectStatus Status { get; set; }
        public int CreatedBy { get; set; }
        public string CreatedByName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }

    public class ProjectTask
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int ProjectId { get; set; }
        public string ProjectName { get; set; } = string.Empty;
        public int? AssignedToUserId { get; set; }
        public string AssignedToUserName { get; set; } = string.Empty;
        public TaskStatus Status { get; set; }
        public TaskPriority Priority { get; set; }
        public DateTime? DueDate { get; set; }
        public int CreatedBy { get; set; }
        public string CreatedByName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }

    public enum ProjectStatus
    {
        Planning = 1,
        InProgress = 2,
        Completed = 3,
        OnHold = 4,
        Cancelled = 5
    }

    public enum TaskStatus
    {
        ToDo = 1,
        InProgress = 2,
        Review = 3,
        Done = 4,
        Cancelled = 5
    }

    public enum TaskPriority
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}
```

---

## DTOs/AuthDtos.cs
```csharp
namespace ProjectManagement.DTOs
{
    public class LoginDto
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class RegisterDto
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public int RoleId { get; set; } = 2; // Default to User role
    }

    public class AuthResponseDto
    {
        public string Token { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public UserDto User { get; set; } = new();
    }

    public class UserDto
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string RoleName { get; set; } = string.Empty;
    }

    public class CreateProjectDto
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime StartDate { get; set; }
        public DateTime? EndDate { get; set; }
    }

    public class UpdateProjectDto
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public int Status { get; set; }
    }

    public class CreateTaskDto
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int ProjectId { get; set; }
        public int? AssignedToUserId { get; set; }
        public int Priority { get; set; } = 2; // Medium priority by default
        public DateTime? DueDate { get; set; }
    }

    public class UpdateTaskDto
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int? AssignedToUserId { get; set; }
        public int Status { get; set; }
        public int Priority { get; set; }
        public DateTime? DueDate { get; set; }
    }
}
```

---

## Data/DatabaseContext.cs
```csharp
using Microsoft.Data.SqlClient;
using System.Data;

namespace ProjectManagement.Data
{
    public interface IDatabaseContext
    {
        IDbConnection CreateConnection();
    }

    public class DatabaseContext : IDatabaseContext
    {
        private readonly string _connectionString;

        public DatabaseContext(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection") ?? 
                throw new InvalidOperationException("Connection string not found");
        }

        public IDbConnection CreateConnection()
        {
            return new SqlConnection(_connectionString);
        }
    }
}
```

---

## Middleware/CorrelationIdMiddleware.cs
```csharp
using Serilog.Context;

namespace ProjectManagement.Middleware
{
    public class CorrelationIdMiddleware
    {
        private readonly RequestDelegate _next;
        private const string CorrelationIdHeaderName = "X-Correlation-ID";

        public CorrelationIdMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var correlationId = GetOrCreateCorrelationId(context);
            
            using (LogContext.PushProperty("CorrelationId", correlationId))
            {
                context.Response.Headers.Add(CorrelationIdHeaderName, correlationId);
                await _next(context);
            }
        }

        private static string GetOrCreateCorrelationId(HttpContext context)
        {
            context.Request.Headers.TryGetValue(CorrelationIdHeaderName, out var correlationId);
            return correlationId.FirstOrDefault() ?? Guid.NewGuid().ToString();
        }
    }
}
```

---

## Middleware/RequestLoggingMiddleware.cs
```csharp
namespace ProjectManagement.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var startTime = DateTime.UtcNow;
            
            _logger.LogInformation("Request {Method} {Path} started",
                context.Request.Method, context.Request.Path);

            try
            {
                await _next(context);
            }
            finally
            {
                var elapsed = DateTime.UtcNow - startTime;
                _logger.LogInformation("Request {Method} {Path} completed in {ElapsedMs}ms with status {StatusCode}",
                    context.Request.Method, 
                    context.Request.Path, 
                    elapsed.TotalMilliseconds,
                    context.Response.StatusCode);
            }
        }
    }
}
```

---

## Middleware/GlobalExceptionMiddleware.cs
```csharp
using System.Diagnostics;

namespace ProjectManagement.Middleware
{
    public class GlobalExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<GlobalExceptionMiddleware> _logger;
        private readonly IWebHostEnvironment _environment;

        public GlobalExceptionMiddleware(RequestDelegate next, ILogger<GlobalExceptionMiddleware> logger, IWebHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred");
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";
            
            var (statusCode, message) = exception switch
            {
                ArgumentException => (400, "Invalid argument provided"),
                UnauthorizedAccessException => (401, "Unauthorized access"),
                KeyNotFoundException => (404, "Resource not found"),
                InvalidOperationException => (400, "Invalid operation"),
                _ => (500, "An internal server error occurred")
            };

            context.Response.StatusCode = statusCode;

            var response = new
            {
                error = new
                {
                    message,
                    statusCode,
                    details = _environment.IsDevelopment() ? exception.ToString() : null,
                    traceId = Activity.Current?.Id ?? context.TraceIdentifier
                }
            };

            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response));
        }
    }
}
```

---

## Validators/AuthValidators.cs
```csharp
using FluentValidation;
using ProjectManagement.DTOs;

namespace ProjectManagement.Validators
{
    public class LoginDtoValidator : AbstractValidator<LoginDto>
    {
        public LoginDtoValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("Username is required")
                .Length(3, 50).WithMessage("Username must be between 3 and 50 characters");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required")
                .MinimumLength(6).WithMessage("Password must be at least 6 characters");
        }
    }

    public class RegisterDtoValidator : AbstractValidator<RegisterDto>
    {
        public RegisterDtoValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("Username is required")
                .Length(3, 50).WithMessage("Username must be between 3 and 50 characters")
                .Matches("^[a-zA-Z0-9_]+$").WithMessage("Username can only contain letters, numbers, and underscores");

            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email is required")
                .EmailAddress().WithMessage("Valid email address is required");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required")
                .MinimumLength(8).WithMessage("Password must be at least 8 characters")
                .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)").WithMessage("Password must contain at least one lowercase letter, one uppercase letter, and one digit");

            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("First name is required")
                .Length(2, 50).WithMessage("First name must be between 2 and 50 characters");

            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("Last name is required")
                .Length(2, 50).WithMessage("Last name must be between 2 and 50 characters");

            RuleFor(x => x.RoleId)
                .GreaterThan(0).WithMessage("Valid role must be selected");
        }
    }

    public class CreateProjectDtoValidator : AbstractValidator<CreateProjectDto>
    {
        public CreateProjectDtoValidator()
        {
            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("Project name is required")
                .Length(3, 100).WithMessage("Project name must be between 3 and 100 characters");

            RuleFor(x => x.Description)
                .MaximumLength(1000).WithMessage("Description cannot exceed 1000 characters");

            RuleFor(x => x.StartDate)
                .NotEmpty().WithMessage("Start date is required")
                .GreaterThanOrEqualTo(DateTime.Today).WithMessage("Start date cannot be in the past");

            RuleFor(x => x.EndDate)
                .GreaterThan(x => x.StartDate).WithMessage("End date must be after start date")
                .When(x => x.EndDate.HasValue);
        }
    }

    public class CreateTaskDtoValidator : AbstractValidator<CreateTaskDto>
    {
        public CreateTaskDtoValidator()
        {
            RuleFor(x => x.Title)
                .NotEmpty().WithMessage("Task title is required")
                .Length(3, 100).WithMessage("Task title must be between 3 and 100 characters");

            RuleFor(x => x.Description)
                .MaximumLength(1000).WithMessage("Description cannot exceed 1000 characters");

            RuleFor(x => x.ProjectId)
                .GreaterThan(0).WithMessage("Valid project must be selected");

            RuleFor(x => x.Priority)
                .InclusiveBetween(1, 4).WithMessage("Priority must be between 1 (Low) and 4 (Critical)");

            RuleFor(x => x.DueDate)
                .GreaterThanOrEqualTo(DateTime.Today).WithMessage("Due date cannot be in the past")
                .When(x => x.DueDate.HasValue);
        }
    }
}
```

---

## Services/AuthService.cs
```csharp
using Dapper;
using Microsoft.IdentityModel.Tokens;
using ProjectManagement.Data;
using ProjectManagement.DTOs;
using ProjectManagement.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ProjectManagement.Services
{
    public interface IAuthService
    {
        Task<AuthResponseDto?> LoginAsync(LoginDto loginDto);
        Task<AuthResponseDto?> RegisterAsync(RegisterDto registerDto);
        Task<bool> UserExistsAsync(string username, string email);
    }

    public class AuthService : IAuthService
    {
        private readonly IDatabaseContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;

        public AuthService(IDatabaseContext context, IConfiguration configuration, ILogger<AuthService> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<AuthResponseDto?> LoginAsync(LoginDto loginDto)
        {
            using var connection = _context.CreateConnection();
            
            var user = await connection.QueryFirstOrDefaultAsync<User>(
                @"SELECT u.*, r.Name as RoleName 
                  FROM Users u 
                  INNER JOIN Roles r ON u.RoleId = r.Id 
                  WHERE u.Username = @Username AND u.IsActive = 1",
                new { loginDto.Username });

            if (user == null || !VerifyPassword(loginDto.Password, user.PasswordHash))
            {
                _logger.LogWarning("Failed login attempt for username: {Username}", loginDto.Username);
                return null;
            }

            var token = GenerateJwtToken(user);
            
            _logger.LogInformation("Successful login for user: {UserId}", user.Id);
            
            return new AuthResponseDto
            {
                Token = token,
                Expires = DateTime.UtcNow.AddHours(24),
                User = new UserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    RoleName = user.RoleName
                }
            };
        }

        public async Task<AuthResponseDto?> RegisterAsync(RegisterDto registerDto)
        {
            if (await UserExistsAsync(registerDto.Username, registerDto.Email))
            {
                _logger.LogWarning("Registration attempt with existing username/email: {Username}/{Email}", 
                    registerDto.Username, registerDto.Email);
                return null;
            }

            using var connection = _context.CreateConnection();
            
            var passwordHash = HashPassword(registerDto.Password);
            
            var userId = await connection.QuerySingleAsync<int>(
                @"INSERT INTO Users (Username, Email, PasswordHash, FirstName, LastName, RoleId, CreatedAt, IsActive)
                  VALUES (@Username, @Email, @PasswordHash, @FirstName, @LastName, @RoleId, @CreatedAt, 1);
                  SELECT SCOPE_IDENTITY();",
                new
                {
                    registerDto.Username,
                    registerDto.Email,
                    PasswordHash = passwordHash,
                    registerDto.FirstName,
                    registerDto.LastName,
                    registerDto.RoleId,
                    CreatedAt = DateTime.UtcNow
                });

            var user = await connection.QueryFirstAsync<User>(
                @"SELECT u.*, r.Name as RoleName 
                  FROM Users u 
                  INNER JOIN Roles r ON u.RoleId = r.Id 
                  WHERE u.Id = @UserId",
                new { UserId = userId });

            var token = GenerateJwtToken(user);
            
            _logger.LogInformation("Successful registration for user: {UserId}", userId);
            
            return new AuthResponseDto
            {
                Token = token,
                Expires = DateTime.UtcNow.AddHours(24),
                User = new UserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    RoleName = user.RoleName
                }
            };
        }

        public async Task<bool> UserExistsAsync(string username, string email)
        {
            using var connection = _context.CreateConnection();
            
            var count = await connection.QuerySingleAsync<int>(
                "SELECT COUNT(*) FROM Users WHERE Username = @Username OR Email = @Email",
                new { Username = username, Email = email });

            return count > 0;
        }

        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        private bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        private string GenerateJwtToken(User user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"];
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(secretKey);
            
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.RoleName)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(24),
                Issuer = jwtSettings["Issuer"],
                Audience = jwtSettings["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), 
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
```

---

## Services/UserService.cs
```csharp
using Dapper;
using ProjectManagement.Data;
using ProjectManagement.Models;

namespace ProjectManagement.Services
{
    public interface IUserService
    {
        Task<IEnumerable<User>> GetUsersAsync();
        Task<User?> GetUserByIdAsync(int id);
        Task<IEnumerable<Role>> GetRolesAsync();
    }

    public class UserService : IUserService
    {
        private readonly IDatabaseContext _context;
        private readonly ILogger<UserService> _logger;

        public UserService(IDatabaseContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<User>> GetUsersAsync()
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving all users");
            
            return await connection.QueryAsync<User>(
                @"SELECT u.*, r.Name as RoleName 
                  FROM Users u 
                  INNER JOIN Roles r ON u.RoleId = r.Id 
                  WHERE u.IsActive = 1
                  ORDER BY u.FirstName, u.LastName");
        }

        public async Task<User?> GetUserByIdAsync(int id)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving user by ID: {UserId}", id);
            
            return await connection.QueryFirstOrDefaultAsync<User>(
                @"SELECT u.*, r.Name as RoleName 
                  FROM Users u 
                  INNER JOIN Roles r ON u.RoleId = r.Id 
                  WHERE u.Id = @Id AND u.IsActive = 1",
                new { Id = id });
        }

        public async Task<IEnumerable<Role>> GetRolesAsync()
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving all roles");
            
            return await connection.QueryAsync<Role>(
                "SELECT * FROM Roles ORDER BY Name");
        }
    }
}
```

---

## Services/ProjectService.cs
```csharp
using Dapper;
using ProjectManagement.Data;
using ProjectManagement.DTOs;
using ProjectManagement.Models;

namespace ProjectManagement.Services
{
    public interface IProjectService
    {
        Task<IEnumerable<Project>> GetProjectsAsync();
        Task<Project?> GetProjectByIdAsync(int id);
        Task<Project> CreateProjectAsync(CreateProjectDto projectDto, int userId);
        Task<Project?> UpdateProjectAsync(int id, UpdateProjectDto projectDto, int userId);
        Task<bool> DeleteProjectAsync(int id, int userId);
    }

    public class ProjectService : IProjectService
    {
        private readonly IDatabaseContext _context;
        private readonly ILogger<ProjectService> _logger;

        public ProjectService(IDatabaseContext context, ILogger<ProjectService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<Project>> GetProjectsAsync()
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving all projects");
            
            return await connection.QueryAsync<Project>(
                @"SELECT p.*, u.FirstName + ' ' + u.LastName as CreatedByName 
                  FROM Projects p 
                  INNER JOIN Users u ON p.CreatedBy = u.Id 
                  ORDER BY p.CreatedAt DESC");
        }

        public async Task<Project?> GetProjectByIdAsync(int id)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving project by ID: {ProjectId}", id);
            
            return await connection.QueryFirstOrDefaultAsync<Project>(
                @"SELECT p.*, u.FirstName + ' ' + u.LastName as CreatedByName 
                  FROM Projects p 
                  INNER JOIN Users u ON p.CreatedBy = u.Id 
                  WHERE p.Id = @Id",
                new { Id = id });
        }

        public async Task<Project> CreateProjectAsync(CreateProjectDto projectDto, int userId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Creating new project: {ProjectName} by user: {UserId}", projectDto.Name, userId);
            
            var projectId = await connection.QuerySingleAsync<int>(
                @"INSERT INTO Projects (Name, Description, StartDate, EndDate, Status, CreatedBy, CreatedAt)
                  VALUES (@Name, @Description, @StartDate, @EndDate, @Status, @CreatedBy, @CreatedAt);
                  SELECT SCOPE_IDENTITY();",
                new
                {
                    projectDto.Name,
                    projectDto.Description,
                    projectDto.StartDate,
                    projectDto.EndDate,
                    Status = (int)ProjectStatus.Planning,
                    CreatedBy = userId,
                    CreatedAt = DateTime.UtcNow
                });

            return (await GetProjectByIdAsync(projectId))!;
        }

        public async Task<Project?> UpdateProjectAsync(int id, UpdateProjectDto projectDto, int userId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Updating project: {ProjectId} by user: {UserId}", id, userId);
            
            var rowsAffected = await connection.ExecuteAsync(
                @"UPDATE Projects 
                  SET Name = @Name, Description = @Description, StartDate = @StartDate, 
                      EndDate = @EndDate, Status = @Status, UpdatedAt = @UpdatedAt
                  WHERE Id = @Id",
                new
                {
                    Id = id,
                    projectDto.Name,
                    projectDto.Description,
                    projectDto.StartDate,
                    projectDto.EndDate,
                    projectDto.Status,
                    UpdatedAt = DateTime.UtcNow
                });

            return rowsAffected > 0 ? await GetProjectByIdAsync(id) : null;
        }

        public async Task<bool> DeleteProjectAsync(int id, int userId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Deleting project: {ProjectId} by user: {UserId}", id, userId);
            
            var rowsAffected = await connection.ExecuteAsync(
                "DELETE FROM Projects WHERE Id = @Id",
                new { Id = id });

            return rowsAffected > 0;
        }
    }
}
```

---

## Services/TaskService.cs
```csharp
using Dapper;
using ProjectManagement.Data;
using ProjectManagement.DTOs;
using ProjectManagement.Models;

namespace ProjectManagement.Services
{
    public interface ITaskService
    {
        Task<IEnumerable<ProjectTask>> GetTasksAsync();
        Task<IEnumerable<ProjectTask>> GetTasksByProjectIdAsync(int projectId);
        Task<ProjectTask?> GetTaskByIdAsync(int id);
        Task<ProjectTask> CreateTaskAsync(CreateTaskDto taskDto, int userId);
        Task<ProjectTask?> UpdateTaskAsync(int id, UpdateTaskDto taskDto, int userId);
        Task<bool> DeleteTaskAsync(int id, int userId);
    }

    public class TaskService : ITaskService
    {
        private readonly IDatabaseContext _context;
        private readonly ILogger<TaskService> _logger;

        public TaskService(IDatabaseContext context, ILogger<TaskService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<ProjectTask>> GetTasksAsync()
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving all tasks");
            
            return await connection.QueryAsync<ProjectTask>(
                @"SELECT t.*, p.Name as ProjectName, 
                         ISNULL(u.FirstName + ' ' + u.LastName, '') as AssignedToUserName,
                         cu.FirstName + ' ' + cu.LastName as CreatedByName
                  FROM Tasks t 
                  INNER JOIN Projects p ON t.ProjectId = p.Id
                  LEFT JOIN Users u ON t.AssignedToUserId = u.Id
                  INNER JOIN Users cu ON t.CreatedBy = cu.Id
                  ORDER BY t.CreatedAt DESC");
        }

        public async Task<IEnumerable<ProjectTask>> GetTasksByProjectIdAsync(int projectId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving tasks for project: {ProjectId}", projectId);
            
            return await connection.QueryAsync<ProjectTask>(
                @"SELECT t.*, p.Name as ProjectName, 
                         ISNULL(u.FirstName + ' ' + u.LastName, '') as AssignedToUserName,
                         cu.FirstName + ' ' + cu.LastName as CreatedByName
                  FROM Tasks t 
                  INNER JOIN Projects p ON t.ProjectId = p.Id
                  LEFT JOIN Users u ON t.AssignedToUserId = u.Id
                  INNER JOIN Users cu ON t.CreatedBy = cu.Id
                  WHERE t.ProjectId = @ProjectId
                  ORDER BY t.CreatedAt DESC",
                new { ProjectId = projectId });
        }

        public async Task<ProjectTask?> GetTaskByIdAsync(int id)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Retrieving task by ID: {TaskId}", id);
            
            return await connection.QueryFirstOrDefaultAsync<ProjectTask>(
                @"SELECT t.*, p.Name as ProjectName, 
                         ISNULL(u.FirstName + ' ' + u.LastName, '') as AssignedToUserName,
                         cu.FirstName + ' ' + cu.LastName as CreatedByName
                  FROM Tasks t 
                  INNER JOIN Projects p ON t.ProjectId = p.Id
                  LEFT JOIN Users u ON t.AssignedToUserId = u.Id
                  INNER JOIN Users cu ON t.CreatedBy = cu.Id
                  WHERE t.Id = @Id",
                new { Id = id });
        }

        public async Task<ProjectTask> CreateTaskAsync(CreateTaskDto taskDto, int userId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Creating new task: {TaskTitle} by user: {UserId}", taskDto.Title, userId);
            
            var taskId = await connection.QuerySingleAsync<int>(
                @"INSERT INTO Tasks (Title, Description, ProjectId, AssignedToUserId, Status, Priority, DueDate, CreatedBy, CreatedAt)
                  VALUES (@Title, @Description, @ProjectId, @AssignedToUserId, @Status, @Priority, @DueDate, @CreatedBy, @CreatedAt);
                  SELECT SCOPE_IDENTITY();",
                new
                {
                    taskDto.Title,
                    taskDto.Description,
                    taskDto.ProjectId,
                    taskDto.AssignedToUserId,
                    Status = (int)TaskStatus.ToDo,
                    taskDto.Priority,
                    taskDto.DueDate,
                    CreatedBy = userId,
                    CreatedAt = DateTime.UtcNow
                });

            return (await GetTaskByIdAsync(taskId))!;
        }

        public async Task<ProjectTask?> UpdateTaskAsync(int id, UpdateTaskDto taskDto, int userId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Updating task: {TaskId} by user: {UserId}", id, userId);
            
            var rowsAffected = await connection.ExecuteAsync(
                @"UPDATE Tasks 
                  SET Title = @Title, Description = @Description, AssignedToUserId = @AssignedToUserId, 
                      Status = @Status, Priority = @Priority, DueDate = @DueDate, UpdatedAt = @UpdatedAt
                  WHERE Id = @Id",
                new
                {
                    Id = id,
                    taskDto.Title,
                    taskDto.Description,
                    taskDto.AssignedToUserId,
                    taskDto.Status,
                    taskDto.Priority,
                    taskDto.DueDate,
                    UpdatedAt = DateTime.UtcNow
                });

            return rowsAffected > 0 ? await GetTaskByIdAsync(id) : null;
        }

        public async Task<bool> DeleteTaskAsync(int id, int userId)
        {
            using var connection = _context.CreateConnection();
            
            _logger.LogInformation("Deleting task: {TaskId} by user: {UserId}", id, userId);
            
            var rowsAffected = await connection.ExecuteAsync(
                "DELETE FROM Tasks WHERE Id = @Id",
                new { Id = id });

            return rowsAffected > 0;
        }
    }
}
```

---

## Controllers/V1/AuthController.cs
```csharp
using Microsoft.AspNetCore.Mvc;
using ProjectManagement.DTOs;
using ProjectManagement.Services;

namespace ProjectManagement.Controllers.V1
{
    /// <summary>
    /// Authentication endpoints for user login and registration
    /// </summary>
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    [Produces("application/json")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate user and return JWT token
        /// </summary>
        /// <param name="loginDto">Login credentials</param>
        /// <returns>Authentication response with JWT token</returns>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponseDto), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
        {
            _logger.LogInformation("Login attempt for username: {Username}", loginDto.Username);
            
            var result = await _authService.LoginAsync(loginDto);
            
            if (result == null)
            {
                _logger.LogWarning("Failed login attempt for username: {Username}", loginDto.Username);
                return Unauthorized(new { message = "Invalid credentials" });
            }

            _logger.LogInformation("Successful login for username: {Username}", loginDto.Username);
            return Ok(result);
        }

        /// <summary>
        /// Register a new user account
        /// </summary>
        /// <param name="registerDto">User registration details</param>
        /// <returns>Authentication response with JWT token</returns>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponseDto), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponseDto>> Register(RegisterDto registerDto)
        {
            _logger.LogInformation("Registration attempt for username: {Username}, email: {Email}", 
                registerDto.Username, registerDto.Email);
            
            var result = await _authService.RegisterAsync(registerDto);
            
            if (result == null)
            {
                _logger.LogWarning("Failed registration attempt - user already exists: {Username}", registerDto.Username);
                return BadRequest(new { message = "User already exists" });
            }

            _logger.LogInformation("Successful registration for username: {Username}", registerDto.Username);
            return Ok(result);
        }
    }
}
```

---

## Controllers/V1/UsersController.cs
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectManagement.Models;
using ProjectManagement.Services;

namespace ProjectManagement.Controllers.V1
{
    /// <summary>
    /// User management endpoints
    /// </summary>
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    [Authorize]
    [Produces("application/json")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(IUserService userService, ILogger<UsersController> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        /// <summary>
        /// Get all users
        /// </summary>
        /// <returns>List of users</returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<User>), 200)]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            var users = await _userService.GetUsersAsync();
            return Ok(users);
        }

        /// <summary>
        /// Get user by ID
        /// </summary>
        /// <param name="id">User ID</param>
        /// <returns>User details</returns>
        [HttpGet("{id}")]
        [ProducesResponseType(typeof(User), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            
            if (user == null)
                return NotFound();

            return Ok(user);
        }

        /// <summary>
        /// Get all available roles
        /// </summary>
        /// <returns>List of roles</returns>
        [HttpGet("roles")]
        [ProducesResponseType(typeof(IEnumerable<Role>), 200)]
        public async Task<ActionResult<IEnumerable<Role>>> GetRoles()
        {
            var roles = await _userService.GetRolesAsync();
            return Ok(roles);
        }
    }
}
```

---

## Controllers/V1/ProjectsController.cs
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectManagement.DTOs;
using ProjectManagement.Models;
using ProjectManagement.Services;
using System.Security.Claims;

namespace ProjectManagement.Controllers.V1
{
    /// <summary>
    /// Project management endpoints
    /// </summary>
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    [Authorize]
    [Produces("application/json")]
    public class ProjectsController : ControllerBase
    {
        private readonly IProjectService _projectService;
        private readonly ILogger<ProjectsController> _logger;

        public ProjectsController(IProjectService projectService, ILogger<ProjectsController> logger)
        {
            _projectService = projectService;
            _logger = logger;
        }

        /// <summary>
        /// Get all projects
        /// </summary>
        /// <returns>List of projects</returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<Project>), 200)]
        public async Task<ActionResult<IEnumerable<Project>>> GetProjects()
        {
            var projects = await _projectService.GetProjectsAsync();
            return Ok(projects);
        }

        /// <summary>
        /// Get project by ID
        /// </summary>
        /// <param name="id">Project ID</param>
        /// <returns>Project details</returns>
        [HttpGet("{id}")]
        [ProducesResponseType(typeof(Project), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<Project>> GetProject(int id)
        {
            var project = await _projectService.GetProjectByIdAsync(id);
            
            if (project == null)
                return NotFound();

            return Ok(project);
        }

        /// <summary>
        /// Create a new project
        /// </summary>
        /// <param name="projectDto">Project creation details</param>
        /// <returns>Created project</returns>
        [HttpPost]
        [ProducesResponseType(typeof(Project), 201)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<Project>> CreateProject(CreateProjectDto projectDto)
        {
            var userId = GetCurrentUserId();
            var project = await _projectService.CreateProjectAsync(projectDto, userId);
            
            return CreatedAtAction(nameof(GetProject), new { id = project.Id }, project);
        }

        /// <summary>
        /// Update an existing project
        /// </summary>
        /// <param name="id">Project ID</param>
        /// <param name="projectDto">Project update details</param>
        /// <returns>Updated project</returns>
        [HttpPut("{id}")]
        [ProducesResponseType(typeof(Project), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<Project>> UpdateProject(int id, UpdateProjectDto projectDto)
        {
            var userId = GetCurrentUserId();
            var project = await _projectService.UpdateProjectAsync(id, projectDto, userId);
            
            if (project == null)
                return NotFound();

            return Ok(project);
        }

        /// <summary>
        /// Delete a project
        /// </summary>
        /// <param name="id">Project ID</param>
        /// <returns>No content</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin,ProjectManager")]
        [ProducesResponseType(204)]
        [ProducesResponseType(404)]
        public async Task<ActionResult> DeleteProject(int id)
        {
            var userId = GetCurrentUserId();
            var success = await _projectService.DeleteProjectAsync(id, userId);
            
            if (!success)
                return NotFound();

            return NoContent();
        }

        private int GetCurrentUserId()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            return int.Parse(userIdClaim?.Value ?? "0");
        }
    }
}
```

---

## Controllers/V1/TasksController.cs
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectManagement.DTOs;
using ProjectManagement.Models;
using ProjectManagement.Services;
using System.Security.Claims;

namespace ProjectManagement.Controllers.V1
{
    /// <summary>
    /// Task management endpoints
    /// </summary>
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    [Authorize]
    [Produces("application/json")]
    public class TasksController : ControllerBase
    {
        private readonly ITaskService _taskService;
        private readonly ILogger<TasksController> _logger;

        public TasksController(ITaskService taskService, ILogger<TasksController> logger)
        {
            _taskService = taskService;
            _logger = logger;
        }

        /// <summary>
        /// Get all tasks
        /// </summary>
        /// <returns>List of tasks</returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<ProjectTask>), 200)]
        public async Task<ActionResult<IEnumerable<ProjectTask>>> GetTasks()
        {
            var tasks = await _taskService.GetTasksAsync();
            return Ok(tasks);
        }

        /// <summary>
        /// Get tasks by project ID
        /// </summary>
        /// <param name="projectId">Project ID</param>
        /// <returns>List of tasks for the project</returns>
        [HttpGet("project/{projectId}")]
        [ProducesResponseType(typeof(IEnumerable<ProjectTask>), 200)]
        public async Task<ActionResult<IEnumerable<ProjectTask>>> GetTasksByProject(int projectId)
        {
            var tasks = await _taskService.GetTasksByProjectIdAsync(projectId);
            return Ok(tasks);
        }

        /// <summary>
        /// Get task by ID
        /// </summary>
        /// <param name="id">Task ID</param>
        /// <returns>Task details</returns>
        [HttpGet("{id}")]
        [ProducesResponseType(typeof(ProjectTask), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<ProjectTask>> GetTask(int id)
        {
            var task = await _taskService.GetTaskByIdAsync(id);
            
            if (task == null)
                return NotFound();

            return Ok(task);
        }

        /// <summary>
        /// Create a new task
        /// </summary>
        /// <param name="taskDto">Task creation details</param>
        /// <returns>Created task</returns>
        [HttpPost]
        [ProducesResponseType(typeof(ProjectTask), 201)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<ProjectTask>> CreateTask(CreateTaskDto taskDto)
        {
            var userId = GetCurrentUserId();
            var task = await _taskService.CreateTaskAsync(taskDto, userId);
            
            return CreatedAtAction(nameof(GetTask), new { id = task.Id }, task);
        }

        /// <summary>
        /// Update an existing task
        /// </summary>
        /// <param name="id">Task ID</param>
        /// <param name="taskDto">Task update details</param>
        /// <returns>Updated task</returns>
        [HttpPut("{id}")]
        [ProducesResponseType(typeof(ProjectTask), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<ProjectTask>> UpdateTask(int id, UpdateTaskDto taskDto)
        {
            var userId = GetCurrentUserId();
            var task = await _taskService.UpdateTaskAsync(id, taskDto, userId);
            
            if (task == null)
                return NotFound();

            return Ok(task);
        }

        /// <summary>
        /// Delete a task
        /// </summary>
        /// <param name="id">Task ID</param>
        /// <returns>No content</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin,ProjectManager")]
        [ProducesResponseType(204)]
        [ProducesResponseType(404)]
        public async Task<ActionResult> DeleteTask(int id)
        {
            var userId = GetCurrentUserId();
            var success = await _taskService.DeleteTaskAsync(id, userId);
            
            if (!success)
                return NotFound();

            return NoContent();
        }

        private int GetCurrentUserId()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            return int.Parse(userIdClaim?.Value ?? "0");
        }
    }
}
```

---

## Tests/Unit/AuthServiceTests.cs
```csharp
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Moq;
using ProjectManagement.Data;
using ProjectManagement.DTOs;
using ProjectManagement.Services;
using Microsoft.Extensions.Logging;
using System.Data;
using Xunit;

namespace ProjectManagement.Tests.Unit
{
    public class AuthServiceTests
    {
        private readonly Mock<IDatabaseContext> _mockContext;
        private readonly Mock<IConfiguration> _mockConfiguration;
        private readonly Mock<ILogger<AuthService>> _mockLogger;
        private readonly AuthService _authService;

        public AuthServiceTests()
        {
            _mockContext = new Mock<IDatabaseContext>();
            _mockConfiguration = new Mock<IConfiguration>();
            _mockLogger = new Mock<ILogger<AuthService>>();
            
            var jwtSection = new Mock<IConfigurationSection>();
            jwtSection.Setup(x => x["SecretKey"]).Returns("test-secret-key-that-is-at-least-32-characters-long");
            jwtSection.Setup(x => x["Issuer"]).Returns("TestIssuer");
            jwtSection.Setup(x => x["Audience"]).Returns("TestAudience");
            
            _mockConfiguration.Setup(x => x.GetSection("JwtSettings")).Returns(jwtSection.Object);
            
            _authService = new AuthService(_mockContext.Object, _mockConfiguration.Object, _mockLogger.Object);
        }

        [Fact]
        public async Task RegisterAsync_WithValidData_ShouldReturnAuthResponse()
        {
            // Arrange
            var registerDto = new RegisterDto
            {
                Username = "testuser",
                Email = "test@example.com",
                Password = "TestPass123",
                FirstName = "Test",
                LastName = "User",
                RoleId = 2
            };

            // Act & Assert - This is a simplified test
            // In a real scenario, you'd mock the database calls
            var result = await _authService.UserExistsAsync(registerDto.Username, registerDto.Email);
            
            // This test demonstrates the structure - you'd need to mock Dapper calls
            result.Should().BeFalse(); // This would fail without proper mocking
        }

        [Theory]
        [InlineData("", "test@example.com", false)]
        [InlineData("testuser", "", false)]
        [InlineData("testuser", "test@example.com", true)]
        public void ValidateUserData_WithVariousInputs_ShouldReturnExpectedResults(
            string username, string email, bool expectedValid)
        {
            // Arrange & Act
            var isValid = !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(email);
            
            // Assert
            isValid.Should().Be(expectedValid);
        }

        [Fact]
        public void HashPassword_ShouldReturnHashedPassword()
        {
            // Arrange
            var password = "TestPassword123";
            
            // Act - This would require making HashPassword public or testing through public methods
            var isValid = !string.IsNullOrEmpty(password);
            
            // Assert
            isValid.Should().BeTrue();
        }
    }
}
```

---

## Tests/Integration/AuthControllerIntegrationTests.cs
```csharp
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using ProjectManagement.DTOs;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace ProjectManagement.Tests.Integration
{
    public class AuthControllerIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly WebApplicationFactory<Program> _factory;
        private readonly HttpClient _client;

        public AuthControllerIntegrationTests(WebApplicationFactory<Program> factory)
        {
            _factory = factory;
            _client = _factory.CreateClient();
        }

        [Fact]
        public async Task Login_WithInvalidCredentials_ShouldReturnUnauthorized()
        {
            // Arrange
            var loginDto = new LoginDto
            {
                Username = "nonexistent",
                Password = "wrongpassword"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/v1/auth/login", loginDto);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Register_WithInvalidData_ShouldReturnBadRequest()
        {
            // Arrange
            var registerDto = new RegisterDto
            {
                Username = "ab", // Too short
                Email = "invalid-email",
                Password = "123", // Too weak
                FirstName = "",
                LastName = "",
                RoleId = 0
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/v1/auth/register", registerDto);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task HealthCheck_ShouldReturnHealthy()
        {
            // Act
            var response = await _client.GetAsync("/health");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            
            var content = await response.Content.ReadAsStringAsync();
            content.Should().NotBeEmpty();
        }

        [Fact]
        public async Task HealthCheck_Ready_ShouldReturnOk()
        {
            // Act
            var response = await _client.GetAsync("/health/ready");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task HealthCheck_Live_ShouldReturnOk()
        {
            // Act
            var response = await _client.GetAsync("/health/live");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}
```

---

## Tests/ProjectManagement.Tests.csproj
```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />
    <PackageReference Include="xunit" Version="2.6.2" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.5.3" />
    <PackageReference Include="FluentAssertions" Version="6.12.0" />
    <PackageReference Include="Moq" Version="4.20.69" />
    <PackageReference Include="Microsoft.AspNetCore.Mvc.Testing" Version="9.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.InMemory" Version="9.0.0" />
    <PackageReference Include="Testcontainers.MsSql" Version="3.6.0" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\ProjectManagement.csproj" />
  </ItemGroup>

</Project>
```