using PasswordVault.Core.Constants;
using PasswordVault.Core.Interfaces;
using PasswordVault.Core.Models;
using PasswordVault.Core.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Core.Services
{
    public class VaultService
    {
        private readonly IVaultStorage _storage;
        private readonly IVaultFileSerializer _serializer;
        private readonly VaultEncryptionService _encryptionService;

        public VaultService(IVaultStorage storage, IVaultFileSerializer serializer, VaultEncryptionService encryptionService)
        {
            _storage = storage;
            _serializer = serializer;
            _encryptionService = encryptionService;
        }

        public async Task CreateVaultAsync(string masterPassword)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

            if (await _storage.LoadAsync() is not null)
                throw new InvalidOperationException("Vault already exists.");

            byte[] salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize);

            var metadata = new VaultFile { Salt = salt };

            byte[] aad = VaultMetadataSerializer.Serialize(metadata);

            byte[] plainText = Encoding.UTF8.GetBytes("""{"entries":[]}""");

            byte[] encryptedData = await _encryptionService.EncryptAsync(plainText, masterPassword, salt, aad);

            var vaultFile = new VaultFile
            {
                Version = metadata.Version,
                KdfAlgorithm = metadata.KdfAlgorithm,
                MemoryKiB = metadata.MemoryKiB,
                Iterations = metadata.Iterations,
                Parallelism = metadata.Parallelism,
                Salt = metadata.Salt,
                EncryptedData = encryptedData
            };

            byte[] serializedData = _serializer.Serialize(vaultFile);

            await _storage.SaveAsync(serializedData);
        }

        public async Task<byte[]> UnlockVaultAsync(string masterPassword)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

            byte[]? storedData = await _storage.LoadAsync();

            if (storedData is null)
                throw new FileNotFoundException("Vault file not found.");

            VaultFile vaultFile = _serializer.Deserialize(storedData);

            byte[] aad = VaultMetadataSerializer.Serialize(vaultFile);

            byte[] decryptedData = await _encryptionService.DecryptAsync(vaultFile.EncryptedData, masterPassword, vaultFile.Salt, aad);

            return decryptedData;
        }
    }
}
