using System.Security.Cryptography;
using PasswordVault.Security;
using Xunit;

namespace PasswordVault.Tests.Security
{
    public class KeyDerivationServiceTests
    {
        [Fact]
        public async Task DeriveKeyAsync_Returns32ByteKey()
        {
            // Arrange
            var service = new KeyDerivationService();

            string password = "testar123";
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            // Act
            byte[] key = await service.DeriveKeyAsync(password, salt);

            // Assert
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public async Task DeriveKeyAsync_SamePasswordAndSalt_ReturnsSameKey()
        {
            var service = new KeyDerivationService();
            
            string password = "testar123";
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            byte[] key1 = await service.DeriveKeyAsync(password, salt);
            byte[] key2 = await service.DeriveKeyAsync(password, salt);

            Assert.Equal(key1, key2);
        }

        [Fact]
        public async Task DeriveKeyAsync_DifferentPasswords_ReturnsDifferentKeys()
        {
            var service = new KeyDerivationService();

            string password1 = "testar123";
            string password2 = "testar456";
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            byte[] key1 = await service.DeriveKeyAsync(password1, salt);
            byte[] key2 = await service.DeriveKeyAsync(password2, salt);

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public async Task DeriveKeyAsync_DifferentSalt_ReturnsDifferentKeys()
        {
            var service = new KeyDerivationService();

            string password = "testar123";
            byte[] salt1 = RandomNumberGenerator.GetBytes(16);
            byte[] salt2 = RandomNumberGenerator.GetBytes(16);

            byte[] key1 = await service.DeriveKeyAsync(password, salt1);
            byte[] key2 = await service.DeriveKeyAsync(password, salt2);

            Assert.NotEqual(key1, key2);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task DeriveKeyAsync_InvalidPassword_ThrowsArgumentException(string? password)
        {
            var service = new KeyDerivationService();

            byte[] salt = RandomNumberGenerator.GetBytes(16);

            await Assert.ThrowsAsync<ArgumentException>(() => service.DeriveKeyAsync(password!, salt));
        }
    }
}
