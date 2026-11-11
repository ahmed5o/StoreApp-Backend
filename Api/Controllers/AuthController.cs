using API.Services;
using Business.DTOs.Auth;
using Business.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace API.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ICurrentUserService _currentUser;
    private readonly IAuthCookieService _authCookieService;

    public AuthController(
        IAuthService authService,
        ICurrentUserService currentUser,
        IAuthCookieService authCookieService)
    {
        _authService = authService;
        _currentUser = currentUser;
        _authCookieService = authCookieService;
    }

    [HttpPost("register")]
    [EnableRateLimiting("UserLimiter")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
    {
        var result = await _authService.RegisterAsync(request);

        if (!result.Success)
            return BadRequest();

        _authCookieService.SetAuthCookies(Response, result);

        return Ok(new
        {
            success = true,
            message = result.Message,
            user = result.User

        });
    }

    [HttpPost("login")]
    [EnableRateLimiting("UserLimiter")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authService.LoginAsync(request, ip);


        _authCookieService.SetAuthCookies(Response, result);

        if (!result.Success)
            return Unauthorized(result);

        return Ok(new
        {
            success = true,
            message = result.Message,
            user = result.User
        });
    }



    [HttpPost("refresh")]
    [EnableRateLimiting("UserLimiter")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh()
    {
        var accessToken = Request.Cookies["accessToken"];
        var refreshToken = Request.Cookies["refreshToken"];

        if (string.IsNullOrWhiteSpace(accessToken) ||
            string.IsNullOrWhiteSpace(refreshToken))
        {
            return Unauthorized(new
            {
                success = false,
                message = "Access token or refresh token is missing."
            });
        }

        var request = new RefreshTokenRequestDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        var result = await _authService.RefreshTokenAsync(request, ip);

        if (!result.Success)
        {
            _authCookieService.ClearAuthCookies(Response);

            return Unauthorized(new
            {
                success = false,
                message = result.Message
            });
        }

        _authCookieService.SetAuthCookies(Response, result);

        return Ok(new
        {
            success = true,
            message = result.Message,
            user = result.User
        });
    }




    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = _currentUser.UserId;

        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        await _authService.LogoutAsync(userId);

        _authCookieService.ClearAuthCookies(Response);

        return Ok(new
        {
            success = true,
            message = "Logged out successfully."
        });
    }
}