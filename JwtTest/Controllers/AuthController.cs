using JwtTest.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtTest.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration) 
        {
            _configuration = configuration;
        }

        /// <summary>
        /// 用戶註冊，並且將密碼自動雜湊加鹽
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash= passwordHash;
            user.PasswordSalt= passwordSalt;
            return Ok(user);
        } 

        /// <summary>
        /// 登入功能，登入成功後會丟一個 Json web token，給前端，前端需要讓這個 token 存在用戶的 cookie 或 localstorage 作為授權使用
        /// </summary>
        /// <param name="request">使用者輸入的帳密</param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("找不到使用者");
            }

            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt)) 
            {
                return  BadRequest("密碼錯誤");
            }
            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            //Claim 的中文叫做宣告，代表主體的屬性
            List<Claim> claims = new List<Claim>
            {
                //使用者的名字
                new Claim(ClaimTypes.Name, user.Username),
                //身分，在這裡可以是外送員、用戶、店家等等
                new Claim(ClaimTypes.Role, "User"),
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("Appsettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken
                (
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials:creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        //將密碼附上雜湊值並加鹽
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt) 
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        /// <summary>
        /// 判斷使用者輸入的密碼是否相符
        /// </summary>
        /// <param name="password">輸入的密碼</param>
        /// <param name="passwordHash">雜湊後的密碼</param>
        /// <param name="passwordSalt">加鹽後的密碼</param>
        /// <returns></returns>
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hamc = new HMACSHA512(passwordSalt)) 
            {
                var computedHash = hamc.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
