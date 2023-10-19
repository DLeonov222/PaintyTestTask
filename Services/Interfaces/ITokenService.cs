using PaintyTest.Wrappers;

namespace PaintyTest.Services.Interfaces;

public interface ITokenService
{
    public string GenerateToken(int id);
    ResultWrapper<bool> ValidateToken(string token, out int accountId);
}
