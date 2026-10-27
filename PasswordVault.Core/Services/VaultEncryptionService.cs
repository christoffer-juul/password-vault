using PasswordVault.Core.Interfaces;
using System.Security.Cryptography;

namespace PasswordVault.Core.Services
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

        public async Task<byte[]> EncryptAsync(byte[] plainText, string masterPassword, byte[] salt, byte[] associatedData)
        {
            ArgumentNullException.ThrowIfNull(associatedData);

            if (associatedData.Length == 0)
                throw new ArgumentException("Associated data cannot be empty.", nameof(associatedData));

            byte[] key = await _keyDerivation.DeriveKeyAsync(masterPassword, salt);

            try
            {
                return _encryption.Encrypt(plainText, key, associatedData);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        public async Task<byte[]> DecryptAsync(byte[] encryptedData, string masterPassword, byte[] salt, byte[] associatedData)
        {
            ArgumentNullException.ThrowIfNull(associatedData);

            if (associatedData.Length == 0)
                throw new ArgumentException("Associated data cannot be empty.", nameof(associatedData));

            byte[] key = await _keyDerivation.DeriveKeyAsync(masterPassword, salt);

            try
            {
                return _encryption.Decrypt(encryptedData, key, associatedData);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }
}
