using Microsoft.AspNetCore.Mvc;
using PaintyTest.Wrappers;

namespace PaintyTest.Services.Interfaces;

public interface IImageService
{
    public Task<ResultWrapper<bool>> LoadImage(byte[] image, string fileName, string contentType);
    public Task<ResultWrapper<bool>> DeleteImage(int imageId);
    public Task<ResultWrapper<List<FileContentResult>>> CheckSelfImages();
    public Task<ResultWrapper<List<FileContentResult>>> CheckFriendsImages(int friendId);
}
