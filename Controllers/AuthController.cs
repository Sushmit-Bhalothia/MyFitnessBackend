using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using MyFitnessBackendApi.Dtos.User;

namespace MyFitnessBackendApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController:ControllerBase
    {
        private readonly IAuthRepository _authRepo;
        public AuthController(IAuthRepository authRepository)
        {
            _authRepo = authRepository;
        }
        [HttpPost("Register")]
      public async Task<ActionResult<ServiceResponse<int>>> Register(UserRegisterDto request)
      {
          var response = await _authRepo.Register(
              new User {Username = request.Username}, request.Password
          );
          if (!response.Success)
          {
              return BadRequest(response);
          }
          return Ok(response);
      }
      [HttpPost("Login")]
        public async Task<ActionResult<ServiceResponse<string>>> Login(UserLoginDto request)
        {
            var response = await _authRepo.Login(request.Username, request.Password);
            if (!response.Success)
            {
                return BadRequest(response);
            }
            return Ok(response);
        }
        
    }
}