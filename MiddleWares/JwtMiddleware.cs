using PaintyTest.Services.Interfaces;

namespace PaintyTest.MiddleWares
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly HttpClient _httpClient;
        private readonly ITokenService _tokenService;

        public JwtMiddleware(RequestDelegate next, HttpClient httpClient, ITokenService tokenService)
        {
            _next = next;
            _httpClient = httpClient;
            _tokenService = tokenService;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (httpContext.Request.Path.Value.Contains("api/Authorization") ||
                httpContext.Request.Path.Value.Contains("api/Register"))
            {
                await  _next(httpContext);
                return;
            }

            var token = httpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            var check = _tokenService.ValidateToken(token, out int accountId);

            if (check.Data)
            {
                httpContext.Items["accountId"] = accountId;
                await _next(httpContext);
            }
            else
            {
                throw new UnauthorizedAccessException();
            }

        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class JwtMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtMiddleware>();
        }
    }
}
