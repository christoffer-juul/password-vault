using PasswordVault.Core.Constants;
using PasswordVault.Security;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Tests.Security
{
    public class AesEncryptionServiceTests
    {
        [Fact]
        public void EncryptThenDecrypt_ReturnsOriginalData()
        {
            // Arrange
            var service = new AesEncryptionService();
            byte[] key = RandomNumberGenerator.GetBytes(32); // 256-bit key
            byte[] original = Encoding.UTF8.GetBytes("testar123");

            // Act
            byte[] encrypted = service.Encrypt(original, key);
            byte[] decrypted = service.Decrypt(encrypted, key);

            // Assert
            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void Decrypt_WithModifiedData_ThrowsCryptographicException()
        {
            // Arrange
            var service = new AesEncryptionService();

            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] original = Encoding.UTF8.GetBytes("testar123");

            byte[] encrypted = service.Encrypt(original, key);

            // Modify the encrypted data to simulate tampering
            encrypted[^1] ^= 0x01;

            // Act & Assert
            Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted, key));
        }

        [Fact]
        public void Decrypt_WithInvalidKey_ThrowsCryptographicException()
        {
            // Arrange
            var service = new AesEncryptionService();

            byte[] correctKey = RandomNumberGenerator.GetBytes(32);
            byte[] wrongKey = RandomNumberGenerator.GetBytes(32);

            byte[] original = Encoding.UTF8.GetBytes("testar123");

            // Encrypt the data with the correct key
            byte[] encrypted = service.Encrypt(original, correctKey);

            // Act & Assert
            Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted, wrongKey));
        }

        [Fact]
        public void Encrypt_WithInvalidKeyLength_ThrowsArgumentException()
        {
            // Arrange
            var service = new AesEncryptionService();

            byte[] invalidKey = RandomNumberGenerator.GetBytes(16); // 128-bit key, should be 256-bit
            byte[] original = Encoding.UTF8.GetBytes("testar123");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => service.Encrypt(original, invalidKey));
        }

        [Fact]
        public void Encrypt_SameDataTwice_ProducesDifferentResults()
        {
            // Arrange
            var service = new AesEncryptionService();

            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] original = Encoding.UTF8.GetBytes("testar123");

            // Act
            byte[] encrypted1 = service.Encrypt(original, key);
            byte[] encrypted2 = service.Encrypt(original, key);

            // Assert
            Assert.False(encrypted1.SequenceEqual(encrypted2));
        }

        [Fact]
        public void Decrypt_WrongAssociatedData_ThrowsCryptographicException()
        {
            var encryptionService = new AesEncryptionService();

            byte[] key = RandomNumberGenerator.GetBytes(VaultConstants.KeySize);

            byte[] plainText = Encoding.UTF8.GetBytes("Testdata");

            byte[] correctAad = Encoding.UTF8.GetBytes("Version=1");
            byte[] wrongAad = Encoding.UTF8.GetBytes("Version=2");

            byte[] encryptedData = encryptionService.Encrypt(plainText, key, correctAad);

            Assert.ThrowsAny<CryptographicException>(() => encryptionService.Decrypt(encryptedData, key, wrongAad));
        }

        [Fact]
        public void EncryptThenDecrypt_CorrectAssociatedData_ReturnsOriginalData()
        {
            var encryptionService = new AesEncryptionService();

            byte[] key = RandomNumberGenerator.GetBytes(VaultConstants.KeySize);

            byte[] plainText = Encoding.UTF8.GetBytes("Testdata");

            byte[] aad = Encoding.UTF8.GetBytes("Version=1");

            byte[] encryptedData = encryptionService.Encrypt(plainText, key, aad);

            byte[] decryptedData = encryptionService.Decrypt(encryptedData, key, aad);

            Assert.Equal(plainText, decryptedData);
        }
    }
}
