using Microsoft.AspNetCore.Mvc;
using sign.Services;

namespace sign.Controllers;

[ApiController]
[Route("[controller]")]
public class HomeController : ControllerBase
{

    private readonly ILogger<HomeController> _logger;

    private readonly ISignature _signature;

    public HomeController(ILogger<HomeController> logger, ISignature signature)
    {
        _logger = logger;
        _signature = signature;
    }

    [HttpGet("ping")]
    public ActionResult<string> Ping()
    {
        return Ok("pong");
    }

    [HttpPost("sign")]
    public IActionResult Sign([FromForm] FileRequest request) {
        
        if (request == null || request.file == null || request.file.ContentType != "application/pdf") {
            return BadRequest();
        }

        var file = request.file;

        using var input_stream = new MemoryStream();

        file.CopyToAsync(input_stream);

        var output_stream = _signature.Sign(input_stream);
        
        return File(output_stream.ToArray(), "application/pdf", file.FileName);

    }

    public class FileRequest {
        public IFormFile? file { get; set; }
    }


}
