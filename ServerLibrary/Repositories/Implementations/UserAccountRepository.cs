﻿using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository (IOptions<JwtSection> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            // Check if the user is null
            if (user is null) return new GeneralResponse(false, "Model is empty");

            // Check if the user is valid
            var checkuser = await FindUserByEmail(user.Email);
            if (checkuser is not null) return new GeneralResponse(false, "User already exists");

            //Save User
            var applicationUser = await AddToDataBase (new ApplicationUser()
            {
                FullName = user.FullName,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // check, create and assign role
            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDataBase(new SystemRole(){Name = Constants.Admin});
                await AddToDataBase(new UserRole(){RoleId = createAdminRole.Id,UserId = applicationUser.Id});
                return new GeneralResponse(true, "Account created!");

            }

            var checkuserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkuserRole is null)
            {
                response = await AddToDataBase(new SystemRole() { Name = Constants.Admin });
                await AddToDataBase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
                
            }
            else
            {
                
                await AddToDataBase(new UserRole() { RoleId = checkuserRole.Id, UserId = applicationUser.Id });
            }
                return new GeneralResponse(true, "Account created!");
        }
        public async Task<LoginResponse> SignInAsync(Login user)
        {
            // Check if the user is null
            if (user is null) return new LoginResponse(false, "Model is empty");


            // Check if the user exists
            var applicationUser = await FindUserByEmail(user.Email!);
            if (applicationUser is null) return new LoginResponse(false, "User not found");

            // Check if the password is correct
            if (!BCrypt.Net.BCrypt.Verify(user.Password!, applicationUser.Password!))
                return new LoginResponse(false, "Email/Password not valid");

            // Check if the user is active
            var getUserRole = await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "User role not found");

            // Check if the user role is valid
            var getRoleName = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "User role not found");

            // Generate JWT token and refresh token
            string jwtToken = GenerateToken(applicationUser, getRoleName.Name!); 
            string refreshToken = GenerateRefreshToken();
            // Save the refresh token to the database
            var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
            if (findUser is not null)
            {
                findUser!.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            }
            else
            {
                await AddToDataBase(new RefreshTokenInfo()
                {
                    Token = refreshToken,
                    UserId = applicationUser.Id
                });
            }
            
                return new LoginResponse(true, "Login sucessfully", jwtToken, refreshToken);

        }
        private string GenerateToken(ApplicationUser user, string role)
        {
            // Get the JWT settings from the configuration
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            // Create the claims for the token
            var UsersClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.FullName!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role)
            };
            // Create the token using the claims and signing credentials
            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: UsersClaims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );
            // Create the token handler and write the token to a string
            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        public async Task<UserRole> FindUserRole(int userId) => await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);
        private async Task<SystemRole> FindUserRoleById(int roleId) => await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId); 

        // Generate a random refresh token
        private string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));


        private async Task<ApplicationUser?> FindUserByEmail(string email)
        {
            return await appDbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Email == email);
        }

        private async Task<T> AddToDataBase<T>(T Model)
        {
            var result = appDbContext.Add(Model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            // Check if the user is null
            if (token is null) return new LoginResponse(false, "Model is empty");

            // Check if the token is valid
            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token == token.Token);
            if (findToken is null) return new LoginResponse(false, "Token not found");

            // Check if the token is expired
            var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);
            if (user is null) return new LoginResponse(false, "RefreshToken could not generate because user not found");

            // Check if the user is active
            var userRole = await FindUserRole(user.Id);
            var roleName = await FindUserRoleById(userRole.RoleId);
            // Check if the user role is valid
            string jwtToken = GenerateToken(user, roleName.Name!);
            string refreshToken = GenerateRefreshToken();

            // Save the new refresh token to the database
            var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == user.Id);
            if (updateRefreshToken is null) return new LoginResponse(false, "RefreshToken could not generate because user not found");

            // Check if the refresh token is expired
            updateRefreshToken.Token = refreshToken;
            await appDbContext.SaveChangesAsync();
            return new LoginResponse(true, "RefreshToken generated successfully", jwtToken, refreshToken);

        }
    }
}
