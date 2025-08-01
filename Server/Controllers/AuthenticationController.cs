﻿using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IUserAccount accountInterface) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync( Register user)
        {
            if (user == null) return BadRequest("Model is empty");
            // Check if the user is valid
            var result = await accountInterface.CreateAsync(user);
            return Ok(result);
        }
        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login user)
        {
            if (user == null) return BadRequest("Model is empty");
            // Check if the user is valid
            var result = await accountInterface.SignInAsync(user);
            return Ok(result);
        }
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync(RefreshToken refreshToken)
        {
            if (refreshToken == null) return BadRequest("Model is empty");
            // Check if the user is valid
            var result = await accountInterface.RefreshTokenAsync(refreshToken);
            return Ok(result);
        }

    }
}
