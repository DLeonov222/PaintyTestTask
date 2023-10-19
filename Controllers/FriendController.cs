using Microsoft.AspNetCore.Mvc;
using PaintyTest.Services.Interfaces;
using PaintyTest.Wrappers;

namespace PaintyTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class FriendController : ControllerBase
{
    private readonly IAccountService _accountService;
    public FriendController(IAccountService accountService) 
    {
        _accountService = accountService;
    }

    [HttpPost("addFriend")]
    public async Task<ResultWrapper<bool>> AddFriend(int friendId)
        => await _accountService.AddFriend(friendId);

    [HttpDelete("removeFriend")]
    public async Task<ResultWrapper<bool>> RemoveFriend(int friendId)
        => await _accountService.RemoveFriend(friendId);
}
