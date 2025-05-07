using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.VisualBasic;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository (IOptions<JwtSection> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user is null) return new GeneralResponse(false, "Model is empty");

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
                await AddToDataBase(new UseRole(){RoleId = createAdminRole.Id,UserId = applicationUser.Id});
                return new GeneralResponse(true, "Account created!");

            }

            var checkuserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkuserRole is null)
            {
                response = await AddToDataBase(new SystemRole() { Name = Constants.Admin });
                await AddToDataBase(new UseRole() { RoleId = response.Id, UserId = applicationUser.Id });
                
            }
            else
            {
                
                await AddToDataBase(new UseRole() { RoleId = checkuserRole.Id, UserId = applicationUser.Id });
            }
                return new GeneralResponse(true, "Account created!");
        }
        public Task<LoginResponse> SignInAsync(Login user)
        {
            throw new NotImplementedException();
        }

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
    }
}
