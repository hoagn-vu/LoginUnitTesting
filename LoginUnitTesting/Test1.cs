using Backend_online_testing.Controllers;
using Backend_online_testing.Dtos;
using Backend_online_testing.Models;
using Backend_online_testing.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using static Backend_online_testing.Controllers.AuthController;


namespace LoginUnitTesting
{
    [TestFixture] // Xác định đây là một class chứa test
    public class Test1
    {
        private Mock<IMongoCollection<UsersModel>> _mockUserCollection;
        private Mock<IMongoDatabase> _mockDatabase;
        private Mock<IConfiguration> _mockConfig;
        private Mock<IAuthService> _mockAuthService;
        private AuthController _controller;



        [SetUp] // Hàm này sẽ chạy trước mỗi test
        public void Setup()
        {
            _mockUserCollection = new Mock<IMongoCollection<UsersModel>>();
            _mockDatabase = new Mock<IMongoDatabase>();
            _mockConfig = new Mock<IConfiguration>();

            _mockDatabase.Setup(db => db.GetCollection<UsersModel>("users", null))
                            .Returns(_mockUserCollection.Object);
            _mockAuthService = new Mock<IAuthService>();
            _controller = new AuthController(_mockAuthService.Object);

        }
         
        [Test] // Đăng nhập thành công
        public async Task Authenticate_ValidUser_ReturnsAuthResponse()
        {
            // Arrange
            var username = "hoangvu";
            var password = "123456";

            var fakeAuthResponse = new AuthResponseDto
            {
                Role = "admin",
                AccessToken = "fake_jwt_token"
            };

            _mockAuthService.Setup(x => x.Authenticate(username, password))
                            .ReturnsAsync(fakeAuthResponse); // Mock giá trị trả về

            // Act
            var result = await _mockAuthService.Object.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.Role, Is.EqualTo("admin"));
            Assert.That(result.AccessToken, Is.EqualTo("fake_jwt_token")); // Kiểm tra token mock
        }



        [Test]
        public async Task Login_InvalidUser_ReturnsUnauthorized()
        {
            // Arrange
            var loginDto = new LoginDto { UserName = "wrongUser", Password = "wrongPass" };

            _mockAuthService.Setup(x => x.Authenticate(loginDto.UserName, loginDto.Password))
                            .ReturnsAsync((AuthResponseDto)null); // Trả về null khi đăng nhập thất bại

            // Act
            var result = await _controller.Login(loginDto);

            // Assert
            var unauthorizedResult = result as UnauthorizedObjectResult;
            Assert.That(unauthorizedResult, Is.Not.Null);
            Assert.That(unauthorizedResult.StatusCode, Is.EqualTo(401));

            Console.WriteLine($"Unauthorized Result Type: {unauthorizedResult.Value?.GetType()}");
            Console.WriteLine($"Unauthorized Result Value: {unauthorizedResult.Value}");

            // Kiểm tra kiểu dữ liệu thực tế
            Assert.That(unauthorizedResult.Value, Is.InstanceOf<ErrorResponseDto>(), "Response should be of type ErrorResponseDto");

            var responseMessage = unauthorizedResult.Value as ErrorResponseDto;
            Assert.That(responseMessage, Is.Not.Null, "Response body should not be null");
            Assert.That(responseMessage.Message, Is.EqualTo("Tài khoản hoặc mật khẩu không chính xác"));
        }

        [Test] // Sai mật khẩu
        public async Task Authenticate_WrongPassword_ReturnsNull()
        {
            // Arrange
            var username = "testuser";
            var wrongPassword = "wrongpassword";
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword("correctpassword");

            var mockUser = new UsersModel { UserName = username, Password = hashedPassword, UserCode = "BIT220089", FullName = "HNV", AccountStatus = "active" };
            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();

            mockCursor.SetupSequence(x => x.MoveNext(It.IsAny<CancellationToken>()))
                      .Returns(true)
                      .Returns(false);
            mockCursor.Setup(x => x.Current).Returns(new List<UsersModel> { mockUser });

            _mockUserCollection.Setup(x => x.FindAsync(It.IsAny<FilterDefinition<UsersModel>>(),
                                                       It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                                                       It.IsAny<CancellationToken>()))
                               .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _mockAuthService.Object.Authenticate(username, wrongPassword);

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test] // Sai tài khoản (không có user này)
        public async Task Authenticate_NonExistentUser_ReturnsNull()
        {
            // Arrange
            var username = "nonexistent";
            var password = "password123";

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.Setup(x => x.MoveNext(It.IsAny<CancellationToken>())).Returns(false);

            _mockUserCollection.Setup(x => x.FindAsync(It.IsAny<FilterDefinition<UsersModel>>(),
                                                       It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                                                       It.IsAny<CancellationToken>()))
                               .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _mockAuthService.Object.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }
    }
}

