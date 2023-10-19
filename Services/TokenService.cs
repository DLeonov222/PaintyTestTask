using Microsoft.IdentityModel.Tokens;
using PaintyTest.Services.Interfaces;
using PaintyTest.Wrappers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PaintyTest.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    public TokenService (IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string GenerateToken(int id)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration.GetValue<string>("SecretJWTKey"));
        var tokenDescriptor = new SecurityTokenDescriptor 
        {
            Subject = new ClaimsIdentity(new List<Claim>() { new Claim("id",id.ToString()) }),
            Expires = DateTime.UtcNow.AddHours(2),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
 
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);

       
        
    }

    public ResultWrapper<bool> ValidateToken(string token, out int accountId)
    {
        if(token == null)
        {
            accountId = -1;
            return new ResultWrapper<bool>()
            {
                Data = false,
                Status = System.Net.HttpStatusCode.BadRequest
            };
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration.GetValue<string>("SecretJWTKey"));

        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            accountId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);
            return new ResultWrapper<bool>()
            {
                Data = true,
                Status = System.Net.HttpStatusCode.OK,
            };
        }
        catch (SecurityTokenExpiredException) 
        {
            throw new UnauthorizedAccessException();
        }
       
       
         
    }

}
