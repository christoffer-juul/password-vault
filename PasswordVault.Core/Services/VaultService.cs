using PasswordVault.Core.Constants;
using PasswordVault.Core.Interfaces;
using PasswordVault.Core.Models;
using System;
using System.Collections.Generic;
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

            byte[] plainText = Encoding.UTF8.GetBytes("""{"entries":[]}""");

            byte[] encryptedData = await _encryptionService.EncryptAsync(plainText, masterPassword, salt);

            var vaultFile = new VaultFile
            {
                Salt = salt,
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

            byte[] decryptedData = await _encryptionService.DecryptAsync(vaultFile.EncryptedData, masterPassword, vaultFile.Salt);

            return decryptedData;
        }
    }
}
