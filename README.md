# JwtTest

本 project 共要安裝 4 個 Nuget 套件  
a. Microsoft.AspNetCore.Authentication.JwtBearer  
b. Microsoft.IdentityModel.Tokens  
c. Swashbuckle.AspNetCore.Filters  
d. System.IdentityModel.Tokens.Jwt  
  
使用程序如下 (資料都是存在記憶體中，沒有使用 database)  
a. 利用 register 註冊帳戶，你會看到妳的帳號、雜湊後的密碼、加鹽後的密碼  
b. 登入，你會看到一個由 header, payload, signature 組成的 Json Web Token (仔細看你會發現他們之間有個 . 分隔開來)，把它複製起來  
c. 使用綠色按鈕 Authorize (沒錯，你在 swagger 透過 套件就能直接進行授權)，輸入 "bearer " + "你的 JWT token"  
d. 可分別藉由 Auth 或 WeatherForecast 測試是否有正確授權，403 權限不相符 (role)、401 代表你沒登入、200代表成功  
  
未來預計更新 refresh token, OAuth2.0 信箱驗證, 修改資料及忘記密碼功能  
