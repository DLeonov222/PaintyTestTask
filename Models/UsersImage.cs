
using System.Text.Json.Serialization;

namespace PaintyTest.Models;

public class UsersImage
{
    public int Id { get; set; }
    public string Path { get; set; }
    public string ContentType{ get; set; }
    public string FileName { get; set; }
    [JsonIgnore]
    public int AccountId { get; set; }
    [JsonIgnore]
    public Account Account { get; set; }
}
