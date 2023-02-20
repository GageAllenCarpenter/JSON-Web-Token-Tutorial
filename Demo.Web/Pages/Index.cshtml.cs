using Demo.Web.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace Demo.Web.Pages
{
    public class IndexModel : PageModel
    {
        public string Jwt { get; set; }

        private readonly HttpClient _httpClient;

        public IndexModel(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public IEnumerable<WeatherForecast> WeatherForecasts { get; set; }

        public async Task OnGetAsync()
        {
            Jwt = Request.Cookies["access_token"];
            WeatherForecasts = await GetWeatherForecastsAsync();
        }

        public async Task<IEnumerable<WeatherForecast>> GetWeatherForecastsAsync()
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7040/WeatherForecast");

                // Add JWT token to the HTTP request header
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Jwt);

                HttpResponseMessage response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    string responseContent = await response.Content.ReadAsStringAsync();
                    IEnumerable<WeatherForecast> weatherForecasts = JsonConvert.DeserializeObject<IEnumerable<WeatherForecast>>(responseContent);
                    return weatherForecasts;
                }
                else
                {
                    // Return "Credentials invalid" if the API request failed with a 401 Unauthorized status code
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return new List<WeatherForecast>();
                    }
                    else
                    {
                        throw new Exception($"API request failed with status code {response.StatusCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"API request failed: {ex.Message}", ex);
            }
        }


    }
}