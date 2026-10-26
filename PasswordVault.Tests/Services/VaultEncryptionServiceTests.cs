using PasswordVault.Core;
using PasswordVault.Core.Services;
using PasswordVault.Security;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Tests.Services
{
    public class VaultEncryptionServiceTests
    {
        [Fact]
        public async Task VaultEncryption_WithCorrectPassword_CanBeDecrypted()
        {
            // Arrange
            var service = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());

            string masterPassword = "testar123!";
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            byte[] originalData = Encoding.UTF8.GetBytes("Secret vault data");

            // Act
            byte[] encryptedData = await service.EncryptAsync(originalData, masterPassword, salt);

            byte[] decryptedData = await service.DecryptAsync(encryptedData, masterPassword, salt);

            // Assert
            Assert.Equal(originalData, decryptedData);
        }

        [Fact]
        public async Task VaultEncryption_WithWrongPassword_ThrowsCryptographicException()
        {
            var service = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());

            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] originalData = Encoding.UTF8.GetBytes("Secret vault data");
            byte[] encryptedData = await service.EncryptAsync(originalData, "testar123!", salt);

            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await service.DecryptAsync(encryptedData, "feltest123", salt));
        }
    }
}
