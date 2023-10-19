using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace PaintyTest.Models;

public class Account : AccountBio
{
    [Key]
    [JsonIgnore]
    public int AccountId { get; set; }

    [JsonIgnore]
    public List<Account>? Friends { get; set; }

    [JsonIgnore]
    public List<Account>? FriendOf { get; set; }

    private List<UsersImage>? _usersImages = new List<UsersImage>();
    [JsonIgnore]
    public IReadOnlyList<UsersImage>? UsersImages => _usersImages.AsReadOnly();

    public void LoadImage(UsersImage image)
        => _usersImages.Add(image);
    
}
