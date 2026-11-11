using Business.DTOs.Auth;
using Microsoft.AspNetCore.Http;

namespace API.Services;

public interface IAuthCookieService
{
    void SetAuthCookies(HttpResponse response, AuthResponseDto result);

    void ClearAuthCookies(HttpResponse response);
}