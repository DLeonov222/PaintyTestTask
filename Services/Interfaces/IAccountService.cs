using PaintyTest.Models;
using PaintyTest.Wrappers;

namespace PaintyTest.Services.Interfaces;

public interface IAccountService
{
    public Task<ResultWrapper<bool>> Register(AccountBio loginInfo);
    public Task<ResultWrapper<string>> Authorization(LoginInfo loginInfo);
    public Task<ResultWrapper<bool>> EditAccountInfo(string name, string surname);
    public Task<ResultWrapper<bool>> EditPassword(string password, string oldPassword);
    public Task<ResultWrapper<bool>> AddFriend(int friendId);
    public Task<ResultWrapper<bool>> RemoveFriend(int friendId);

}
