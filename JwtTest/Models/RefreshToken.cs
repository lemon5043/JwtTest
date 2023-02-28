namespace JwtTest.Models
{
    public class RefreshToken
    {
        //建在資料庫裡會再多設一個 tokenID
        public string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires { get; set; }
    }
}
