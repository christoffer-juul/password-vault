using PasswordVault.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Core
{
    public class VaultEncryptionService
    {
        private readonly IKeyDerivationService _keyDerivation;
        private readonly IEncryptionService _encryption;

        public VaultEncryptionService(IKeyDerivationService keyDerivation, IEncryptionService encryption)
        {
            _keyDerivation = keyDerivation;
            _encryption = encryption;
        }

        public async Task<byte[]> EncryptAsync(byte[] plainText, string masterPassword, byte[] salt)
        {
            byte[] key = await _keyDerivation.DeriveKeyAsync(masterPassword, salt);

            try
            {
                return _encryption.Encrypt(plainText, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        public async Task<byte[]> DecryptAsync(byte[] encryptedData, string masterPassword, byte[] salt)
        {
            byte[] key = await _keyDerivation.DeriveKeyAsync(masterPassword, salt);

            try
            {
                return _encryption.Decrypt(encryptedData, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }
}
