using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //��� controller �� methods ���ݱ��v�~�i�ϥ�
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

        //�Y�O�o�� API �Q�n���ϥΪ̵n�J�~��ϥΡA�N�� Authorize
        //[HttpGet(Name = "GetWeatherForecast"), Authorize]

        //���\�ϥΪ̥����v�Y�i�ϥγo�� API
        //[HttpGet(Name = "GetWeatherForecast"), AllowAnonymous]
        
        // role �� admin ���H�~�i�ϥ�
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