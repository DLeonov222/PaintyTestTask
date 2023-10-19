using Microsoft.AspNetCore.Mvc;
using PaintyTest.Models;
using PaintyTest.Services.Interfaces;
using PaintyTest.Wrappers;

namespace PaintyTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly IAccountService _accountService;
    public AuthorizationController(IAccountService accountService ) 
    { 
        _accountService = accountService;
    }

    [HttpPost("authorize")]
    public async Task<ResultWrapper<string>> Authorize(LoginInfo loginInfo)
        => await _accountService.Authorization(loginInfo);
}
