using System.Net;

namespace PaintyTest.Wrappers;

public class ResultWrapper<T>
{
    public HttpStatusCode Status {  get; set; }
    public T? Data { get; set; }
}
