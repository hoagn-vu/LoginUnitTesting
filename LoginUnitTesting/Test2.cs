using Backend_online_testing.Models;
using Backend_online_testing.Services;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using Moq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using BCryptNet = BCrypt.Net.BCrypt;
using System.Threading.Tasks;
using Backend_online_testing.Dtos;
using DocumentFormat.OpenXml.Spreadsheet;
using NUnit.Framework.Internal;

namespace LoginUnitTesting
{
    [TestFixture]
    public class Test2
    {
        private Mock<IMongoCollection<UsersModel>> _mockUsersCollection;
        private Mock<IMongoDatabase> _mockDatabase;
        private Mock<IConfiguration> _mockConfig;
        private AuthService _authService;
        private Mock<IConfigurationSection> _mockJwtSettings;

        [SetUp]
        public void Setup()
        {
            _mockUsersCollection = new Mock<IMongoCollection<UsersModel>>();
            _mockDatabase = new Mock<IMongoDatabase>();
            _mockConfig = new Mock<IConfiguration>();
            _mockJwtSettings = new Mock<IConfigurationSection>();

            _mockDatabase.Setup(d => d.GetCollection<UsersModel>("users", null))
                .Returns(_mockUsersCollection.Object);

            // Mock JWT settings
            _mockConfig.Setup(c => c.GetSection("JwtSettings")).Returns(_mockJwtSettings.Object);
            _mockJwtSettings.Setup(j => j["Secret"]).Returns("very_secret_key_that_is_long_enough");
            _mockJwtSettings.Setup(j => j["Issuer"]).Returns("test_issuer");
            _mockJwtSettings.Setup(j => j["Audience"]).Returns("test_audience");
            _mockJwtSettings.Setup(j => j["AccessTokenExpirationMinutes"]).Returns("30");
            //_mockJwtSettings.Setup(j => j["RefreshTokenExpirationDays"]).Returns("7");
            // Trong phương thức Setup()
            _mockJwtSettings.Setup(j => j["RefreshTokenExpirationDays"]).Returns("7"); // Thêm dòng này
            _authService = new AuthService(_mockDatabase.Object, _mockConfig.Object);
        }

        // Đăng nhập thành công
        [Test]
        public async Task Authenticate_WithValidCredentials_ReturnsAuthResponse()
        {
            // Arrange
            var username = "testuser";
            var password = "testpass";
            var hashedPassword = BCryptNet.HashPassword(password);

            var testUser = new UsersModel
            {
                Id = "123",
                UserName = username,
                Password = hashedPassword,
                Role = "User",
                UserCode = "TEST001",
                FullName = "Test User",
                AccountStatus = "Active",
                RefreshToken = "old_refresh_token", // Thêm dòng này
                TokenExpiration = DateTime.UtcNow.AddDays(1) // Thêm dòng này
            };

            // Mock JWT settings đầy đủ
            _mockJwtSettings.Setup(j => j["Secret"]).Returns("very_secret_key_that_is_long_enough");
            _mockJwtSettings.Setup(j => j["Issuer"]).Returns("test_issuer");
            _mockJwtSettings.Setup(j => j["Audience"]).Returns("test_audience");
            _mockJwtSettings.Setup(j => j["AccessTokenExpirationMinutes"]).Returns("30");
            _mockJwtSettings.Setup(j => j["RefreshTokenExpirationDays"]).Returns("7"); // Đảm bảo có dòng này

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            _mockUsersCollection.Setup(x => x.UpdateOneAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<UpdateDefinition<UsersModel>>(),
                It.IsAny<UpdateOptions>(),
                default))
                .ReturnsAsync(new UpdateResult.Acknowledged(1, 1, null));

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.AccessToken, Is.Not.Null);
            Assert.That(result.RefreshToken, Is.Not.Null);
            Assert.That(result.Role, Is.EqualTo("User"));
            Assert.That(result.RefreshToken, Is.Not.EqualTo("old_refresh_token")); // Kiểm tra refresh token mới

            // Verify token
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(result.AccessToken);
            Assert.That(token.Subject, Is.EqualTo("123"));
            Assert.That(token.Claims.First(c => c.Type == ClaimTypes.Name).Value, Is.EqualTo("testuser"));
            Assert.That(token.Claims.First(c => c.Type == ClaimTypes.Role).Value, Is.EqualTo("User"));
        }

        // Username không tồn tại
        [Test]
        public async Task Authenticate_WithInvalidUsername_ReturnsNull()
        {
            // Arrange
            var username = "nonexistent";
            var password = "testpass";

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(false);

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }

        // Username trống
        [Test]
        public async Task Authenticate_WithEmptyUsername_ReturnsNull()
        {
            // Arrange
            var username = "";
            var password = "testpass";

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(false);

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }

        // Username null
        [Test]
        public async Task Authenticate_WithNullUsername_ReturnsNull()
        {
            // Arrange
            string? username = null;
            var password = "testpass";

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(false);

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }

        // Sai mật khẩu
        [Test]
        public async Task Authenticate_WithInvalidPassword_ReturnsNull()
        {
            // Arrange
            var username = "testuser";
            var password = "wrongpass";
            var hashedPassword = BCryptNet.HashPassword("correctpass");

            var testUser = new UsersModel
            {
                Id = "123",
                UserName = username,
                Password = hashedPassword,
                Role = "User",
                UserCode = "TEST001", // Added required field
                FullName = "Test User", // Added required field
                AccountStatus = "Active" // Added required field
            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }

        // mật khẩu rỗng
        [Test]
        public async Task Authenticate_WithEmptyPassword_ReturnsNull()
        {
            // Arrange
            var username = "testuser";
            var password = "";
            var hashedPassword = BCryptNet.HashPassword("correctpass");

            var testUser = new UsersModel
            {
                Id = "123",
                UserName = username,
                Password = hashedPassword,
                Role = "User",
                UserCode = "TEST001", // Added required field
                FullName = "Test User", // Added required field
                AccountStatus = "Active" // Added required field
            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }

        // mật khẩu null
        [Test]
        public async Task Authenticate_WithNullPassword_ReturnsNull()
        {
            // Arrange
            var username = "testuser";
            string? password = null;
            var hashedPassword = BCryptNet.HashPassword("correctpass");

            var testUser = new UsersModel
            {
                Id = "123",
                UserName = username,
                Password = hashedPassword,
                Role = "User",
                UserCode = "TEST001", // Added required field
                FullName = "Test User", // Added required field
                AccountStatus = "Active" // Added required field
            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert
            Assert.That(result, Is.Null);
        }

        // Kiểm tra việc tạo JWT token có đúng định dạng và chứa thông tin chính xác không
        [Test]
        public async Task Authenticate_GeneratesValidJwtToken()
        {
            // Arrange
            var username = "testuser";
            var password = "testpass";
            var hashedPassword = BCryptNet.HashPassword(password);

            var testUser = new UsersModel
            {
                Id = "123",
                UserName = username,
                Password = hashedPassword,
                Role = "User",
                UserCode = "TEST001",
                FullName = "Test User",
                AccountStatus = "Active"
            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            _mockUsersCollection.Setup(x => x.UpdateOneAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<UpdateDefinition<UsersModel>>(),
                It.IsAny<UpdateOptions>(),
                default))
                .ReturnsAsync(new UpdateResult.Acknowledged(1, 1, null));

            // Make sure all required configuration values are properly mocked
            _mockJwtSettings.Setup(j => j["Secret"]).Returns("test_secret_key_that_is_long_enough");
            _mockJwtSettings.Setup(j => j["Issuer"]).Returns("test_issuer");
            _mockJwtSettings.Setup(j => j["Audience"]).Returns("test_audience");
            _mockJwtSettings.Setup(j => j["AccessTokenExpirationMinutes"]).Returns("30");
            _mockJwtSettings.Setup(j => j["RefreshTokenExpirationDays"]).Returns("7"); // This was missing

            // Act
            var result = await _authService.Authenticate(username, password);

            // Assert - verify the token was generated correctly
            Assert.That(result, Is.Not.Null);
            Assert.That(result.AccessToken, Is.Not.Null);
            Assert.That(result.RefreshToken, Is.Not.Null);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(result.AccessToken);

            Assert.That(token.Subject, Is.EqualTo("123"));
            Assert.That(token.Claims.First(c => c.Type == ClaimTypes.Name).Value, Is.EqualTo("testuser"));
            Assert.That(token.Claims.First(c => c.Type == ClaimTypes.Role).Value, Is.EqualTo("User"));
        }

        // Kiểm tra hệ thống có throw exception khi thiếu cấu hình JWT secret
        [Test]
        public async Task Authenticate_WithMissingJwtSecret_Throws()
        {
            // Arrange
            var username = "testuser";
            var password = "testpass";

            var testUser = new UsersModel
            {
                Id = "123",
                UserName = username,
                Password = BCryptNet.HashPassword(password),
                Role = "User",
                UserCode = "TEST001",
                FullName = "Test User",
                AccountStatus = "Active"
            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Set secret to null to simulate missing configuration
            _mockJwtSettings.Setup(j => j["Secret"]).Returns((string)null);

            // Act & Assert
            Assert.That(async () => await _authService.Authenticate(username, password),
                Throws.InvalidOperationException);
        }

        // Kiểm tra việc refresh token với token hợp lệ
        [Test]
        public async Task RefreshToken_WithValidToken_ReturnsNewTokens()
        {
            // Arrange
            var refreshToken = "valid_refresh_token";
            var testUser = new UsersModel
            {
                Id = "123",
                UserName = "testuser",
                Role = "User",
                TokenExpiration = DateTime.UtcNow.AddDays(1),
                UserCode = "TEST001", // Added required field
                FullName = "Test User", // Added required field
                AccountStatus = "Active", // Added required field
                Password = "123456"

            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            _mockUsersCollection.Setup(x => x.UpdateOneAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<UpdateDefinition<UsersModel>>(),
                It.IsAny<UpdateOptions>(),
                default))
                .ReturnsAsync(new UpdateResult.Acknowledged(1, 1, null));

            // Act
            var result = await _authService.RefreshToken(refreshToken);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result.AccessToken, Is.Not.Null);
            Assert.That(result.RefreshToken, Is.Not.Null);
            Assert.That(result.RefreshToken, Is.Not.EqualTo(refreshToken));
        }

        // Kiểm tra hệ thống xử lý thế nào với refresh token hết hạn
        [Test]
        public async Task RefreshToken_WithExpiredToken_ReturnsNull()
        {
            // Arrange
            var refreshToken = "expired_refresh_token";
            var testUser = new UsersModel
            {
                Id = "123",
                UserName = "testuser",
                Role = "User",
                TokenExpiration = DateTime.UtcNow.AddDays(-1), // Expired
                UserCode = "TEST001", // Added required field
                FullName = "Test User", // Added required field
                AccountStatus = "Active", // Added required field
                Password = "123456"
            };

            var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
            mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
                .ReturnsAsync(true)
                .ReturnsAsync(false);
            mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

            _mockUsersCollection.Setup(x => x.FindAsync(
                It.IsAny<FilterDefinition<UsersModel>>(),
                It.IsAny<FindOptions<UsersModel, UsersModel>>(),
                default))
                .ReturnsAsync(mockCursor.Object);

            // Act
            var result = await _authService.RefreshToken(refreshToken);

            // Assert
            Assert.That(result, Is.Null);
        }

    //    // Test Case 1: Khi RefreshTokenExpirationDays là chuỗi số hợp lệ
    //    [Test]
    //    public async Task RefreshToken_WithValidExpirationDaysConfig_UpdatesTokenWithConfigValue()
    //    {
    //        // Arrange
    //        var refreshToken = "valid_token";
    //        var testUser = new UsersModel
    //        {
    //            Id = "123",
    //            RefreshToken = refreshToken,
    //            TokenExpiration = DateTime.UtcNow.AddDays(1),
    //            UserName = "testuser",
    //            Role = "User",
    //            UserCode = "TEST001", // Added required field
    //            FullName = "Test User", // Added required field
    //            AccountStatus = "Active", // Added required field
    //            Password = "123456"
    //        };

    //        // Mock để trả về giá trị hợp lệ
    //        _mockJwtSettings.Setup(j => j["RefreshTokenExpirationDays"]).Returns("14"); // Khác giá trị mặc định (7)

    //        // ... (phần mock khác giống như test case RefreshToken_WithValidToken_ReturnsNewTokens)

    //        // Act
    //        var result = await _authService.RefreshToken(refreshToken);

    //        // Assert
    //        _mockUsersCollection.Verify(x => x.UpdateOneAsync(
    //            It.IsAny<FilterDefinition<UsersModel>>(),
    //            It.Is<UpdateDefinition<UsersModel>>(u =>
    //                u.Render(documentSerializer: null).Contains("TokenExpiration")),
    //            It.IsAny<UpdateOptions>(),
    //            default), Times.Once);
    //    }

    //    // Khi RefreshTokenExpirationDays là chuỗi không hợp lệ
    //    [Test]
    //    public async Task RefreshToken_WithInvalidExpirationDaysConfig_UsesDefaultValue()
    //    {
    //        // Arrange
    //        var refreshToken = "valid_token";
    //        var testUser = new UsersModel
    //        {
    //            Id = "123",
    //            RefreshToken = refreshToken,
    //            TokenExpiration = DateTime.UtcNow.AddDays(1),
    //            UserName = "testuser",
    //            Role = "User",
    //            UserCode = "TEST001", // Added required field
    //            FullName = "Test User", // Added required field
    //            AccountStatus = "Active", // Added required field
    //            Password = "123456"
    //        };

    //        // Mock trả về chuỗi không phải số
    //        _mockJwtSettings.Setup(j => j["RefreshTokenExpirationDays"]).Returns("invalid");

    //        // Act & Assert
    //        var result = await _authService.RefreshToken(refreshToken);

    //        // Verify sử dụng giá trị mặc định 7 ngày
    //        _mockUsersCollection.Verify(x => x.UpdateOneAsync(
    //            It.IsAny<FilterDefinition<UsersModel>>(),
    //            It.Is<UpdateDefinition<UsersModel>>(u =>
    //                ((DateTime)u["$set"]["TokenExpiration"]).Day == DateTime.UtcNow.AddDays(7).Day),
    //            It.IsAny<UpdateOptions>(),
    //            default), Times.Once);
    //    }

    //    // GetUserProfile  Test Case 1: Khi user tồn tại
    //    [Test]
    //    public async Task GetUserProfile_WithValidUserId_ReturnsUserDto()
    //    {
    //        // Arrange
    //        var userId = "123";
    //        var testUser = new UsersModel
    //        {
    //            Id = userId,
    //            UserName = "testuser",
    //            Role = "User",
    //            UserCode = "TEST001", // Added required field
    //            FullName = "Test User", // Added required field
    //            AccountStatus = "Active", // Added required field
    //            Password = "123456"
    //        };

    //        var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
    //        mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
    //            .ReturnsAsync(true)
    //            .ReturnsAsync(false);
    //        mockCursor.Setup(_ => _.Current).Returns(new[] { testUser });

    //        // Thay đổi phần mock:
    //        _mockUsersCollection.Setup(x => x.FindAsync(
    //            It.IsAny<FilterDefinition<UsersModel>>(),
    //            It.IsAny<FindOptions<UsersModel, UsersModel>>(), // Thay UserDto bằng UsersModel
    //            default))
    //            .ReturnsAsync(mockCursor.Object);

    //        // Act
    //        var result = await _authService.GetUserProfile(userId);

    //        // Assert
    //        Assert.That(result, Is.Not.Null);
    //        Assert.That(result.Id, Is.EqualTo(userId));
    //        // ... kiểm tra các thuộc tính khác
    //    }

    //    // Khi user không tồn tại
    //    [Test]
    //    public async Task GetUserProfile_WithInvalidUserId_ReturnsNull()
    //    {
    //        // Arrange
    //        var userId = "nonexistent";
    //        var mockCursor = new Mock<IAsyncCursor<UsersModel>>();
    //        mockCursor.SetupSequence(_ => _.MoveNextAsync(default))
    //            .ReturnsAsync(false);

    //        _mockUsersCollection.Setup(x => x.FindAsync(
    //            It.IsAny<FilterDefinition<UsersModel>>(),
    //            It.IsAny<FindOptions<UsersModel, UserDto>>(),
    //            default))
    //            .ReturnsAsync(mockCursor.Object);

    //        // Act
    //        var result = await _authService.GetUserProfile(userId);

    //        // Assert
    //        Assert.That(result, Is.Null);
    //    }

    //    // Kiểm thử nhánh if (user == null) trong GenerateJwtToken
    //    [Test]
    //    public void GenerateJwtToken_WithNullUser_ThrowsArgumentNullException()
    //    {
    //        // Arrange
    //        UsersModel nullUser = null;

    //        // Act & Assert
    //        Assert.That(() => _authService.GenerateJwtToken(nullUser),
    //            Throws.ArgumentNullException
    //                .With.Property("ParamName")
    //                .EqualTo("user"));
    //    }

    //    //Kiểm thử các giá trị null trong GetUserProfile Test Case: Khi các thuộc tính optional là null
    //    [Test]
    //    public async Task GetUserProfile_WithNullOptionalProperties_ReturnsDefaultValues()
    //    {
    //        // Arrange
    //        var userId = "123";
    //        var testUser = new UsersModel
    //        {
    //            Id = userId,
    //            UserName = "testuser",
    //            Role = null,
    //            Gender = null,
    //            UserCode = "TEST001", // Added required field
    //            FullName = "Test User", // Added required field
    //            AccountStatus = "Active", // Added required field
    //            Password = "123456"
    //        };

    //        // ... mock như các test case trước

    //        // Act
    //        var result = await _authService.GetUserProfile(userId);

    //        // Assert
    //        Assert.That(result.Role, Is.EqualTo(string.Empty));
    //        Assert.That(result.Gender, Is.EqualTo(string.Empty));
    //        // ... kiểm tra các giá trị mặc định khác
    //    }
    }
}
