using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace myApi.Controllers
{
    [Route("api/")]
    [ApiController]
    [Authorize]
    public class ValuesController : ControllerBase
    {
        [HttpGet("values")]
        [AllowAnonymous]
        public IActionResult GetValues()
        {
            var test = this.User.Identity.Name;
            List<string> values = new List<string>() { "yoban", "zac", "pal" };
            return Ok(values);
        }

        [HttpGet("secretvalues")]
        public IActionResult GetSecretValues()
        {
            var test = this.User.Identity.Name;
            List<string> values = new List<string>() { "secret", "this", "is","hope","u","are","authenticated" };
            return Ok(values);
        }


        [HttpPost("gettoken")]
        [AllowAnonymous]
        public IActionResult GetToken(string username, string password)
        {

            if(username == "jobin" && password == "jobin")
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes("J0BANIY0BANIJ0BANIY0BANIJ0BANIY0BANIJ0BANIY0BANIJ0BANIY0BANI");
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[] {
                        new Claim(ClaimTypes.Name, "jobina"),
                        new Claim("A", "daBeast") // add all the claims you want in here.
                    }),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);
                return Ok(new { Token = tokenString });
            }
            else
            {
                return Unauthorized("invalid - try again");
            }
        }

    }
}
