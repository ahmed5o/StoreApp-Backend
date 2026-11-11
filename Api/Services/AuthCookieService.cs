using Business.DTOs.Auth;

namespace API.Services;

public class AuthCookieService : IAuthCookieService
{
    public void SetAuthCookies(HttpResponse response, AuthResponseDto result)
    {
        var accessToken = result.AccessToken!;
        var refreshToken = result.RefreshToken!;

        response.Cookies.Append("accessToken", accessToken.Token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/",
            Expires = accessToken.ExpiresAt
        });

        response.Cookies.Append("refreshToken", refreshToken.Token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/api/auth",
            Expires = refreshToken.ExpiresAt
        });
    }

    public void ClearAuthCookies(HttpResponse response)
    {
        response.Cookies.Delete("accessToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/"
        });

        response.Cookies.Delete("refreshToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/api/auth"
        });
    }
}
