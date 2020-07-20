using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Filter
{
    [AttributeUsage(AttributeTargets.Method)]
    public class ApikeyAuth : Attribute, IAsyncActionFilter
    {
        private const string KeyHeaderName = "AuthApiKey";
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(KeyHeaderName, out var key))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var apikey = config.GetValue<string>(KeyHeaderName);
            if (!apikey.Equals(key))
            {
                context.Result = new UnauthorizedResult();
                return;
            }
            await next();
        }
    }
}