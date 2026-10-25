using PasswordVault.Core.Constants;
using PasswordVault.Core.Interfaces;

namespace PasswordVault.Storage
{
    public class FileVaultStorage : IVaultStorage
    {
        private readonly string _filePath;

        public FileVaultStorage(string filePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

            _filePath = Path.GetFullPath(filePath);
        }

        public async Task SaveAsync(byte[] encryptedVault)
        {
            ArgumentNullException.ThrowIfNull(encryptedVault);

            if (encryptedVault.Length > VaultConstants.MaxVaultFileSize)
                throw new InvalidDataException("Vault file exceeds maximum size.");

            string directory = Path.GetDirectoryName(_filePath)!;

            Directory.CreateDirectory(directory);

            string tempPath = Path.Combine(directory, $".{Path.GetFileName(_filePath)}.{Guid.NewGuid():N}.tmp");

            try
            {
                await File.WriteAllBytesAsync(tempPath, encryptedVault);

                File.Move(tempPath, _filePath, overwrite: true);
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
        }

        public async Task<byte[]?> LoadAsync()
        {
            if (!File.Exists(_filePath))
                return null;

            FileInfo fileInfo = new FileInfo(_filePath);

            if (fileInfo.Length > VaultConstants.MaxVaultFileSize)
                throw new InvalidDataException("Vault file exceeds maximum size.");

            return await File.ReadAllBytesAsync(_filePath);
        }
    }
}
