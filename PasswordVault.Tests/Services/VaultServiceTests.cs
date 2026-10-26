using PasswordVault.Core.Services;
using PasswordVault.Security;
using PasswordVault.Storage;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Tests.Services
{
    public class VaultServiceTests
    {
        [Fact]
        public async Task CreateVaultAsync_ValidPassword_CreatesEncryptedVault()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            try
            {
                await vaultService.CreateVaultAsync(masterPassword);

                Assert.True(File.Exists(filePath));

                byte[]? storedData = await storage.LoadAsync();

                Assert.NotNull(storedData);

                var vaultFile = serializer.Deserialize(storedData!);

                byte[] decryptedData = await encryptionService.DecryptAsync(vaultFile.EncryptedData, masterPassword, vaultFile.Salt);

                string content = Encoding.UTF8.GetString(decryptedData);

                Assert.Equal("""{"entries":[]}""", content);
            }
            finally
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        }

        [Fact]
        public async Task CreateVaultAsync_ExistingVault_ThrowsInvalidOperationException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            try
            {
                await vaultService.CreateVaultAsync(masterPassword);

                byte[]? originalData = await storage.LoadAsync();

                Assert.NotNull(originalData);

                await Assert.ThrowsAsync<InvalidOperationException>(() => vaultService.CreateVaultAsync(masterPassword));

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(originalData, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("   ")]
        public async Task CreateVaultAsync_EmptyPassword_ThrowsArgumentException(string masterPassword)
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            try
            {
                await Assert.ThrowsAsync<ArgumentException>(() => vaultService.CreateVaultAsync(masterPassword));

                Assert.False(File.Exists(filePath));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task UnlockVaultAsync_CorrectPassword_ReturnsVaultContent()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            try
            {
                await vaultService.CreateVaultAsync(masterPassword);

                byte[] decryptedData = await vaultService.UnlockVaultAsync(masterPassword);

                string content = Encoding.UTF8.GetString(decryptedData);

                Assert.Equal("""{"entries":[]}""", content);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task UnlockVaultAsync_WrongPassword_ThrowsCryptographicException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string correctPassword = "testar123!";
            string wrongPassword = "fel123!";
            
            try
            {
                await vaultService.CreateVaultAsync(correctPassword);

                await Assert.ThrowsAnyAsync<CryptographicException>(() => vaultService.UnlockVaultAsync(wrongPassword));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task UnlockVaultAsync_VaultDoesNotExist_ThrowsFileNotFoundException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            await Assert.ThrowsAsync<FileNotFoundException>(() => vaultService.UnlockVaultAsync(masterPassword));
        }

        [Fact]
        public async Task UnlockVaultAsync_CorruptedFile_ThrowsInvalidDataException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            byte[] corruptedData = Encoding.UTF8.GetBytes("""{"Version": 1,""");

            try
            {
                await storage.SaveAsync(corruptedData);

                await Assert.ThrowsAsync<InvalidDataException>(() => vaultService.UnlockVaultAsync(masterPassword));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }
    }
}
