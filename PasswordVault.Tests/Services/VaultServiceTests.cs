using PasswordVault.Core.Serialization;
using PasswordVault.Core.Services;
using PasswordVault.Security;
using PasswordVault.Storage;
using PasswordVault.Core.Models;
using System.Security.Cryptography;
using System.Text;
using PasswordVault.Core.Constants;
using PasswordVault.Core.Exceptions;

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

                VaultFile vaultFile = serializer.Deserialize(storedData);

                byte[] aad = VaultMetadataSerializer.Serialize(vaultFile);

                byte[] decryptedData = await encryptionService.DecryptAsync(vaultFile.EncryptedData, masterPassword, vaultFile.Salt, aad);

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

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Empty(vault.Entries);
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
                await storage.SaveNewAsync(corruptedData);

                await Assert.ThrowsAsync<InvalidDataException>(() => vaultService.UnlockVaultAsync(masterPassword));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task CreateVaultAsync_UsesMetadataAsAad()
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

                byte[]? storedData = await storage.LoadAsync();

                Assert.NotNull(storedData);

                VaultFile vaultFile = serializer.Deserialize(storedData);

                byte[] aad = VaultMetadataSerializer.Serialize(vaultFile);

                byte[] decryptedData = await encryptionService.DecryptAsync(vaultFile.EncryptedData, masterPassword, vaultFile.Salt, aad);

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
        public async Task UnlockVaultAsync_MissingAad_ThrowsCryptographicException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var keyDerivation = new KeyDerivationService();
            var aesEncryption = new AesEncryptionService();

            var encryptionService = new VaultEncryptionService(keyDerivation, aesEncryption);

            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            byte[] salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize);

            try
            {
                byte[] plainText = Encoding.UTF8.GetBytes("""{"entries":[]}""");

                byte[] key = await keyDerivation.DeriveKeyAsync(masterPassword, salt);

                byte[] encryptedData;

                try
                {
                    encryptedData = aesEncryption.Encrypt(plainText, key);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }

                var vaultFile = new VaultFile { Salt = salt, EncryptedData = encryptedData };

                await storage.SaveNewAsync(serializer.Serialize(vaultFile));

                await Assert.ThrowsAnyAsync<CryptographicException>(() => vaultService.UnlockVaultAsync(masterPassword));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task UnlockVaultAsync_CorrectPassword_ReturnsEmptyVault()
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

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.NotNull(vault);
                Assert.Empty(vault.Entries);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveVaultAsync_ValidVault_SavesPasswordEntries()
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

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                var entry = new PasswordEntry
                {
                    Title = "Test Entry",
                    Username = "test@example.com",
                    Password = "testar123",
                    Url = "https://example.com"
                };

                vault.AddEntry(entry);

                await vaultService.SaveVaultAsync(vault, masterPassword);

                Vault loadedVault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Single(loadedVault.Entries);

                PasswordEntry loadedEntry = loadedVault.Entries[0];

                Assert.Equal(entry.Id, loadedEntry.Id);
                Assert.Equal(entry.Title, loadedEntry.Title);
                Assert.Equal(entry.Username, loadedEntry.Username);
                Assert.Equal(entry.Password, loadedEntry.Password);
                Assert.Equal(entry.Url, loadedEntry.Url);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveVaultAsync_WrongPassword_DoesNotOverwriteVault()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";
            string wrongPassword = "fel123!";

            try
            {
                await vaultService.CreateVaultAsync(masterPassword);

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                var entry = new PasswordEntry
                {
                    Title = "Test Entry",
                    Username = "test@example.com",
                    Password = "testar123",
                    Url = "https://example.com"
                };

                vault.AddEntry(entry);

                await vaultService.SaveVaultAsync(vault, masterPassword);

                byte[]? originalFileData = await storage.LoadAsync();
                Assert.NotNull(originalFileData);

                await Assert.ThrowsAnyAsync<CryptographicException>(
                    () => vaultService.SaveVaultAsync(vault, wrongPassword));

                byte[]? fileDataAfterFailedSave = await storage.LoadAsync();
                Assert.NotNull(fileDataAfterFailedSave);

                Assert.Equal(originalFileData, fileDataAfterFailedSave);

                Vault loadedVault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Single(loadedVault.Entries);

                PasswordEntry loadedEntry = loadedVault.Entries[0];

                Assert.Equal(entry.Id, loadedEntry.Id);
                Assert.Equal(entry.Title, loadedEntry.Title);
                Assert.Equal(entry.Username, loadedEntry.Username);
                Assert.Equal(entry.Password, loadedEntry.Password);
                Assert.Equal(entry.Url, loadedEntry.Url);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveVaultAsync_VaultDoesNotExist_ThrowsFileNotFoundException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);
            var serializer = new VaultFileSerializer();

            var encryptionService = new VaultEncryptionService(new KeyDerivationService(), new AesEncryptionService());
            var vaultService = new VaultService(storage, serializer, encryptionService);

            string masterPassword = "testar123!";

            var vault = new Vault();

            await Assert.ThrowsAsync<FileNotFoundException>(() => vaultService.SaveVaultAsync(vault, masterPassword));
            Assert.False(File.Exists(filePath));
        }

        [Fact]
        public async Task SaveVaultAsync_UpdatedEntry_PersistsChanges()
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

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                var entry = new PasswordEntry
                {
                    Title = "Test",
                    Username = "old@example.com",
                    Password = "oldpassword123"
                };

                vault.AddEntry(entry);

                await vaultService.SaveVaultAsync(vault, masterPassword);

                var updatedEntry = new PasswordEntry
                {
                    Id = entry.Id,
                    Title = "Test",
                    Username = "new@example.com",
                    Password = "newpassword456"
                };

                vault.UpdateEntry(updatedEntry);

                await vaultService.SaveVaultAsync(vault, masterPassword);

                Vault loadedVault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Single(loadedVault.Entries);

                PasswordEntry loadedEntry = loadedVault.Entries[0];

                Assert.Equal(entry.Id, loadedEntry.Id);
                Assert.Equal("new@example.com", loadedEntry.Username);
                Assert.Equal("newpassword456", loadedEntry.Password);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveVaultAsync_RemovedEntry_PersistsChanges()
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

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                var githubEntry = new PasswordEntry
                {
                    Title = "GitHub",
                    Username = "github@example.com",
                    Password = "password123"
                };

                var discordEntry = new PasswordEntry
                {
                    Title = "Discord",
                    Username = "discord@example.com",
                    Password = "password456"
                };

                vault.AddEntry(githubEntry);
                vault.AddEntry(discordEntry);

                await vaultService.SaveVaultAsync(vault, masterPassword);

                vault.RemoveEntry(githubEntry.Id);

                await vaultService.SaveVaultAsync(vault, masterPassword);

                Vault loadedVault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Single(loadedVault.Entries);

                PasswordEntry remainingEntry = loadedVault.Entries[0];

                Assert.Equal(discordEntry.Id, remainingEntry.Id);
                Assert.Equal(discordEntry.Title, remainingEntry.Title);
                Assert.Equal(discordEntry.Password, remainingEntry.Password);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveVaultAsync_StaleVault_DoesNotOverwriteNewerChanges()
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

                Vault vaultA = await vaultService.UnlockVaultAsync(masterPassword);
                Vault vaultB = await vaultService.UnlockVaultAsync(masterPassword);

                var githubEntry = new PasswordEntry
                {
                    Title = "GitHub",
                    Username = "github@example.com",
                    Password = "password123"
                };

                vaultA.AddEntry(githubEntry);

                await vaultService.SaveVaultAsync(vaultA, masterPassword);

                byte[]? originalFileData = await storage.LoadAsync();

                Assert.NotNull(originalFileData);

                var discordEntry = new PasswordEntry
                {
                    Title = "Discord",
                    Username = "discord@example.com",
                    Password = "password456"
                };

                vaultB.AddEntry(discordEntry);

                await Assert.ThrowsAsync<VaultConflictException>(() => vaultService.SaveVaultAsync(vaultB, masterPassword));

                byte[]? fileDataAfter = await storage.LoadAsync();

                Assert.NotNull(fileDataAfter);
                Assert.Equal(originalFileData, fileDataAfter);

                Vault loadedVault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Single(loadedVault.Entries);
                Assert.Equal(githubEntry.Id, loadedVault.Entries[0].Id);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task UnlockVaultAsync_ExistingVault_SetsSourceVersion()
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

                byte[]? fileData = await storage.LoadAsync();
                Assert.NotNull(fileData);

                string expectedVersion = Convert.ToHexString(SHA256.HashData(fileData));

                Vault vault = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.Equal(expectedVersion, vault.SourceVersion);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task UnlockVaultAsync_SameFile_ReturnsSameSourceVersion()
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

                Vault vaultA = await vaultService.UnlockVaultAsync(masterPassword);
                Vault vaultB = await vaultService.UnlockVaultAsync(masterPassword);

                Assert.NotNull(vaultA.SourceVersion);
                Assert.Equal(vaultA.SourceVersion, vaultB.SourceVersion);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }
    }
}
