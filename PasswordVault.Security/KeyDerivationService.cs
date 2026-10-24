using Konscious.Security.Cryptography;
using PasswordVault.Core.Constants;
using PasswordVault.Core.Interfaces;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Security
{
    public class KeyDerivationService : IKeyDerivationService
    {
        private const int KeySize = 32; // 256 bits
        private const int SaltSize = 16; // 128 bits

        public async Task<byte[]> DeriveKeyAsync(string password, byte[] salt)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.", nameof(password));
            }

            ArgumentNullException.ThrowIfNull(salt);

            if (salt.Length != SaltSize)
            {
                throw new ArgumentException("Salt must be 16 bytes.", nameof(salt));
            }

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            try
            {
                using var argon2 = new Argon2id(passwordBytes)
                {
                    Salt = salt,
                    MemorySize = VaultConstants.Argon2MemoryKiB,
                    Iterations = VaultConstants.Argon2Iterations,
                    DegreeOfParallelism = VaultConstants.Argon2Parallelism
                };

                return await argon2.GetBytesAsync(KeySize);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }
        }
    }
}
