using JwtTest.Models;
using Microsoft.AspNetCore.Authorization;
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
        /// 找出使用者的個人資料
        /// </summary>
        /// <returns></returns>
        [HttpGet, Authorize]
        public ActionResult<object> GetMe()
        {
            var username = User?.Identity?.Name;
            var username2 = User?.FindFirstValue(ClaimTypes.Name);
            var role = User?.FindFirstValue(ClaimTypes.Role);
            return Ok(new {username, username2, role});
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
        /// 登入功能，登入成功後會丟一個 Json web token，給前端，前端需要讓這個 token 存在用戶的 cookie 或 localstorage 作為授權使用，
        /// 另外也生成 refresh token
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

            //登入後除了 JWT access token，也生成一個 refresh token
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if(!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Refresh Token 不相符");
            } else if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Refresh Token 已過期");
            }

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken (newRefreshToken);

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
                new Claim(ClaimTypes.Role, "User")
                //除此之外，Claim 還可以做非常多事情，請自己去查~
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

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires,
            };
            //建立一個 refreshToken 的 cookie
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            //有在資料庫裡設 foreign key 就不需要下面 3 行的code
            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }

        /// <summary>
        /// 將密碼附上雜湊值並加鹽
        /// </summary>
        /// <param name="password">使用者的密碼</param>
        /// <param name="passwordHash">雜湊後的密碼</param>
        /// <param name="passwordSalt">加鹽後的密碼</param>
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
