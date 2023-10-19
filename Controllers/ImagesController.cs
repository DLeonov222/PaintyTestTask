using Microsoft.AspNetCore.Mvc;
using PaintyTest.Services.Interfaces;
using PaintyTest.Wrappers;

namespace PaintyTest.Controllers;

[Route("api/[controller]")]
[ApiController]
public class ImagesController : ControllerBase
{
    private readonly IImageService _imageService;
    public ImagesController(IImageService imageService)
    {
        _imageService = imageService;
    }

    [HttpGet("getSelfImages")]
    public async Task<ResultWrapper<List<FileContentResult>>> GetSelfImages()
        => await _imageService.CheckSelfImages();
    
    [HttpGet("getFriendsImages")]
    public async Task<ResultWrapper<List<FileContentResult>>> GetFriendsImages(int accountId)
        => await _imageService.CheckFriendsImages(accountId);

    [HttpPost("loadImage")]
    public async Task<ResultWrapper<bool>> LoadImage(IFormFile formFile)
    {
        MemoryStream stream = new MemoryStream();
        formFile.CopyTo(stream);
        var result = await _imageService.LoadImage(stream.ToArray(), formFile.FileName, formFile.ContentType);
        stream.Close();
        return result;
    }

    [HttpDelete]
    public async Task<ResultWrapper<bool>> DeleteImage(int fileId)
        =>await _imageService.DeleteImage(fileId);
        
}
