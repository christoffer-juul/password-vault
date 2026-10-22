using PasswordVault.Core.Interfaces;
using System.Security.Cryptography;

namespace PasswordVault.Security
{
    public class AesEncryptionService : IEncryptionService
    {
        private const int KeySize = 32; // 256 bits
        private const int NonceSize = 12; // 96 bits for GCM
        private const int TagSize = 16; // 128 bits for GCM

        public byte[] Encrypt(byte[] plainText, byte[] key)
        {
            ValidateKey(key);
            ArgumentNullException.ThrowIfNull(plainText);

            // Generate a random nonce for each encryption operation
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

            // Create a buffer to hold the ciphertext and the authentication tag
            byte[] ciphertext = new byte[plainText.Length];
            byte[] tag = new byte[TagSize];

            // Perform encryption using AES-GCM
            using var aes = new AesGcm(key, TagSize);

            // Encrypt the plaintext
            aes.Encrypt(nonce, plainText, ciphertext, tag);

            // Combine nonce, tag, and ciphertext into a single byte array for storage or transmission
            return [.. nonce, ..  tag, .. ciphertext];
        }

        public byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            ValidateKey(key);
            ArgumentNullException.ThrowIfNull(encryptedData);

            if (encryptedData.Length < NonceSize + TagSize)
            {
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));
            }

            // Extract the nonce, tag, and ciphertext from the encrypted data
            byte[] nonce = encryptedData[..NonceSize];
            byte[] tag = encryptedData[NonceSize..(NonceSize + TagSize)];
            byte[] ciphertext = encryptedData[(NonceSize + TagSize)..];
            byte[] plainText = new byte[ciphertext.Length];

            using var aes = new AesGcm(key, TagSize);

            try
            {
                // Decrypt and verify the authenticity of the ciphertext
                aes.Decrypt(nonce, ciphertext, tag, plainText);

                return plainText;
            }
            catch (CryptographicException)
            {
                // Clear the plaintext buffer to prevent sensitive data from lingering in memory
                CryptographicOperations.ZeroMemory(plainText);
                throw;
            }
        }

        private static void ValidateKey(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);

            if (key.Length != KeySize)
            {
                throw new ArgumentException($"AES-256 requires a 32-byte key.", nameof(key));
            }
        }
    }
}
