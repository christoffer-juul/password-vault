using PasswordVault.Core;
using PasswordVault.Core.Constants;
using PasswordVault.Core.Models;
using PasswordVault.Core.Services;
using PasswordVault.Security;
using PasswordVault.Storage;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Tests.Integration;

public class VaultIntegrationTests
{
    [Fact]
    public async Task SaveThenLoadVault_ReturnsOriginalData()
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            Guid.NewGuid().ToString());

        string filePath = Path.Combine(directory, "vault.dat");

        var storage = new FileVaultStorage(filePath);
        var serializer = new VaultFileSerializer();

        var encryptionService = new VaultEncryptionService(
            new KeyDerivationService(),
            new AesEncryptionService());

        string masterPassword = "TestPassword123!";

        byte[] originalData = Encoding.UTF8.GetBytes(
            """{"entries":[]}""");

        byte[] salt = RandomNumberGenerator.GetBytes(
            VaultConstants.SaltSize);

        byte[] aad = Encoding.UTF8.GetBytes("TestAAD");

        try
        {
            byte[] encryptedData =
                await encryptionService.EncryptAsync(originalData, masterPassword, salt, aad);

            var vaultFile = new VaultFile
            {
                Salt = salt,
                EncryptedData = encryptedData
            };

            byte[] serializedData = serializer.Serialize(vaultFile);

            await storage.SaveNewAsync(serializedData);

            byte[]? loadedData = await storage.LoadAsync();

            Assert.NotNull(loadedData);

            VaultFile loadedVault = serializer.Deserialize(loadedData);

            byte[] decryptedData = await encryptionService.DecryptAsync(loadedVault.EncryptedData, masterPassword, loadedVault.Salt, aad);

            Assert.Equal(originalData, decryptedData);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}