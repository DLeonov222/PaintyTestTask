using Microsoft.AspNetCore.Mvc;
using PaintyTest.Services.Interfaces;
using PaintyTest.Wrappers;

namespace PaintyTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly IAccountService _accountService;
    public AccountController(IAccountService accountService)
    { 
        _accountService = accountService;
    }

    [HttpPost("EditBio")]
    public async Task<ResultWrapper<bool>> EditBio(string name, string surname)
        => await _accountService.EditAccountInfo(name, surname);

    [HttpPost("EditPassword")]
    public async Task<ResultWrapper<bool>> EditPassword(string password, string oldPassword)
        => await _accountService.EditPassword(password,oldPassword);

}
