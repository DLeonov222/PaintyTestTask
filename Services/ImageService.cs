using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PaintyTest.ApplicationContexts;
using PaintyTest.Models;
using PaintyTest.Services.Interfaces;
using PaintyTest.Wrappers;

namespace PaintyTest.Services;

public class ImageService : IImageService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;


    public ImageService(IHttpContextAccessor httpContextAccessor, ApplicationDbContext applicationDbContext,
        IConfiguration configuration)
    {
        _httpContextAccessor = httpContextAccessor;
        _context = applicationDbContext;
        _configuration = configuration;
    }

    public async Task<ResultWrapper<List<FileContentResult>>> CheckFriendsImages(int friendId)
    {
        var selfId = _httpContextAccessor.HttpContext.Items["accountId"];
        if (selfId is null)
            throw new UnauthorizedAccessException();

        var account = await _context.Accounts.Include(x => x.UsersImages)
            .Include(x => x.FriendOf).ThenInclude(x=>x.UsersImages)
            .FirstOrDefaultAsync(x => x.AccountId == (int)selfId);

        if (account is null)
            throw new Exception();

        if (!account.FriendOf.Any(x => x.AccountId == friendId))
            throw new KeyNotFoundException();

        var friend = await _context.Accounts.FirstOrDefaultAsync(x => x.AccountId == friendId);

        if (friend is null)
            return new ResultWrapper<List<FileContentResult>>()
            {
                Data = null,
                Status = System.Net.HttpStatusCode.InternalServerError,
            };

        List<FileContentResult> images = new();
        foreach (var image in friend.UsersImages)
        {
            var loadImage = File.ReadAllBytes(".\\" + _configuration.GetValue<string>("FilePath") + image.Path);


            images.Add(new FileContentResult(loadImage, image.ContentType));
        }
        return new ResultWrapper<List<FileContentResult>>()
        {
            Data = images,
            Status = System.Net.HttpStatusCode.OK
        };

    }

    public async Task<ResultWrapper<List<FileContentResult>>> CheckSelfImages()
    {
        var selfId = _httpContextAccessor.HttpContext.Items["accountId"];
        if (selfId is null)
            throw new UnauthorizedAccessException();

        var account = await _context.Accounts.Include(x => x.UsersImages)
            .FirstOrDefaultAsync(x => x.AccountId == (int)selfId);

        if (account is null)
            throw new Exception();


        List<FileContentResult> images = new();
        foreach (var image in account.UsersImages)
        {
            var loadImage = File.ReadAllBytes(".\\" + _configuration.GetValue<string>("FilePath") + image.Path);


            images.Add(new FileContentResult(loadImage, image.ContentType));
        }
        return new ResultWrapper<List<FileContentResult>>()
        {
            Data = images,
            Status = System.Net.HttpStatusCode.OK
        };


    }

    public async Task<ResultWrapper<bool>> DeleteImage(int imageId)
    {
        var selfId = _httpContextAccessor.HttpContext.Items["accountId"];
        if (selfId is null)
            throw new UnauthorizedAccessException();

        var account = await _context.Accounts.Include(x => x.UsersImages)
            .FirstOrDefaultAsync(x => x.AccountId == (int)selfId);

        if (account is null)
            throw new Exception();

        var image = account.UsersImages.FirstOrDefault(x=>x.Id == imageId);
        
        if(image is null)
            throw new KeyNotFoundException();

        var fileForDelete = ".\\" + _configuration.GetValue<string>("FilePath") + image.Path;
        File.Delete(fileForDelete);
        _context.UsersImages.Remove(image);
        await _context.SaveChangesAsync();
        return new ResultWrapper<bool>()
        {
            Data = true,
            Status = System.Net.HttpStatusCode.OK
        };
    }

    public async Task<ResultWrapper<bool>> LoadImage(byte[] image, string fileName, string contentType)
    {
        var selfId = _httpContextAccessor.HttpContext.Items["accountId"];
        if (selfId is null)
            throw new UnauthorizedAccessException();

        var account = await _context.Accounts.Include(x => x.UsersImages)
            .FirstOrDefaultAsync(x => x.AccountId == (int)selfId);

        if (account is null)
            throw new Exception();

        var savingPath = $"\\{selfId}\\{fileName}";

        var accountDir = ".\\" + _configuration.GetValue<string>("FilePath") + $"\\{selfId}\\";
        Directory.CreateDirectory(accountDir);

        File.WriteAllBytes(accountDir + fileName, image);

        var userImage = new UsersImage()
        {
            Path = savingPath,
            ContentType = contentType,
            FileName = fileName,
        };

        account.LoadImage(userImage);
        _context.Accounts.Update(account);
        await _context.SaveChangesAsync();
        return new ResultWrapper<bool>()
        {
            Data = true,
            Status = System.Net.HttpStatusCode.OK
        };


    }


}
