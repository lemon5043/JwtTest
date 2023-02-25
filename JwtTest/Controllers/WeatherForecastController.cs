using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //整個 controller 的 methods 都需授權才可使用
    [Authorize]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        //若是這個 API 想要讓使用者登入才能使用，就用 Authorize
        //[HttpGet(Name = "GetWeatherForecast"), Authorize]

        //允許使用者未授權即可使用這個 API
        //[HttpGet(Name = "GetWeatherForecast"), AllowAnonymous]
        
        // role 為 admin 的人才可使用
        [HttpGet(Name = "GetWeatherForecast"), Authorize(Roles = "Admin")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}