using Konscious.Security.Cryptography;
using PasswordVault.Core.Interfaces;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Security
{
    public class KeyDerivationService : IKeyDerivationService
    {
        private const int KeySize = 32; // 256 bits
        private const int SaltSize = 16; // 128 bits

        private const int  MemorySize = 19456; // 19 MB
        private const int Iterations = 2; // Number of iterations for the key derivation function
        private const int Parallelism = 1; // Degree of parallelism for the key derivation function

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
                    MemorySize = MemorySize,
                    Iterations = Iterations,
                    DegreeOfParallelism = Parallelism
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
