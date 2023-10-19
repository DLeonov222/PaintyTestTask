using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using PaintyTest.ApplicationContexts;
using PaintyTest.MiddleWares;
using PaintyTest.Services;
using PaintyTest.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();

builder.Services.AddTransient<ITokenService, TokenService>();

builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IImageService, ImageService>();

builder.Services.AddDbContext<ApplicationDbContext>(
    options =>
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString("DbConnectionString"));
        options.EnableSensitiveDataLogging();
    }
    );
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


builder.Services.AddSwaggerGen(c =>
   {
       var jwtSecurityScheme = new OpenApiSecurityScheme
       {
           Scheme = "Bearer",
           BearerFormat = "JWT",
           Name = "JWT Authentication",
           In = ParameterLocation.Header,
           Type = SecuritySchemeType.Http,
           Description = "Укажите Ваш JWT token в поле ниже",
           Reference = new OpenApiReference
           {
               Id = JwtBearerDefaults.AuthenticationScheme,
               Type = ReferenceType.SecurityScheme
           }
       };

       c.AddSecurityDefinition(jwtSecurityScheme.Reference.Id, jwtSecurityScheme);

       c.AddSecurityRequirement(new OpenApiSecurityRequirement{
                    {
                        jwtSecurityScheme, Array.Empty<string>()
                    }
                });
   });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseExceptionHandlerMiddleware();
app.UseJwtMiddleware();
app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
