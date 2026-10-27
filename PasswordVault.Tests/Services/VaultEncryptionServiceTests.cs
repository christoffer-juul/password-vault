using PasswordVault.Core.Constants;
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
            byte[] aad = Encoding.UTF8.GetBytes("TestAAD");

            // Act
            byte[] encryptedData = await service.EncryptAsync(originalData, masterPassword, salt, aad);

            byte[] decryptedData = await service.DecryptAsync(encryptedData, masterPassword, salt, aad);

            // Assert
            Assert.Equal(originalData, decryptedData);
        }

        [Fact]
        public async Task VaultEncryption_WithWrongPassword_ThrowsCryptographicException()
        {
            var service = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());

            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] originalData = Encoding.UTF8.GetBytes("Secret vault data");
            byte[] aad = Encoding.UTF8.GetBytes("TestAAD");

            byte[] encryptedData = await service.EncryptAsync(originalData, "testar123!", salt, aad);

            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await service.DecryptAsync(encryptedData, "feltest123", salt, aad));
        }

        [Fact]
        public async Task DecryptAsync_WrongAssociatedData_ThrowsCryptographicException()
        {
            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());

            string masterPassword = "testar123!";

            byte[] salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize);

            byte[] plainText = Encoding.UTF8.GetBytes("Testdata");

            byte[] correctAad = Encoding.UTF8.GetBytes("Version=1");
            byte[] wrongAad = Encoding.UTF8.GetBytes("Version=2");

            byte[] encryptedData = await encryptionService.EncryptAsync(plainText, masterPassword, salt, correctAad);

            await Assert.ThrowsAnyAsync<CryptographicException>(() => encryptionService.DecryptAsync(encryptedData, masterPassword, salt, wrongAad));
        }

        [Fact]
        public async Task EncryptThenDecrypt_CorrectAssociatedData_ReturnsOriginalData()
        {
            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());

            string masterPassword = "testar123!";

            byte[] salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize);

            byte[] plainText = Encoding.UTF8.GetBytes("Testdata");

            byte[] aad = Encoding.UTF8.GetBytes("Version=1");

            byte[] encryptedData = await encryptionService.EncryptAsync(plainText, masterPassword, salt, aad);
            byte[] decryptedData = await encryptionService.DecryptAsync(encryptedData, masterPassword, salt, aad);

            Assert.Equal(plainText, decryptedData);
        }

        [Fact]
        public async Task EncryptAsync_EmptyAad_ThrowsArgumentException()
        {
            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());

            byte[] plainText = Encoding.UTF8.GetBytes("Testdata");
            byte[] salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize);

            byte[] emptyAad = [];

            await Assert.ThrowsAsync<ArgumentException>(() => encryptionService.EncryptAsync(plainText, "testar123!", salt, emptyAad));
        }
    }
}
