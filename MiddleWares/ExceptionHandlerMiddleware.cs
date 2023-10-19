using PaintyTest.Wrappers;
using System.Net;
using System.Text.Json;

namespace PaintyTest.MiddleWares
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class ExceptionHandlerMiddleware
    {
        private readonly RequestDelegate _next;

        public ExceptionHandlerMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            try
            {
                await _next(httpContext);
            }
            catch (Exception ex)
            {
                if (!httpContext.Response.HasStarted)
                {
                    ResultWrapper<bool> result = new()
                    {             
                       Data = false
                    };
                    httpContext.Response.StatusCode = ex switch
                    {
                        UnauthorizedAccessException => (int)HttpStatusCode.Unauthorized,              
                        ArgumentException  => (int)HttpStatusCode.BadRequest,
                        KeyNotFoundException => (int)HttpStatusCode.NotFound,
                        _ => (int)HttpStatusCode.InternalServerError,
                    };

                    result.Status = (HttpStatusCode)httpContext.Response.StatusCode;
                    var json = JsonSerializer.Serialize(result);
                    await httpContext.Response.WriteAsync(json);
                }
                

            }
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class ExceptionHandlerMiddlewareExtensions
    {
        public static IApplicationBuilder UseExceptionHandlerMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ExceptionHandlerMiddleware>();
        }
    }
}
