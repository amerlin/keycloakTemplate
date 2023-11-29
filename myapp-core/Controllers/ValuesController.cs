namespace myapp_core.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;

    [Route("[controller]")]
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "User")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        [HttpGet(Name = "GetValues")]
        public IEnumerable<WeatherForecast> Get()
        {
            return new List<WeatherForecast>();
        }
    }
}
