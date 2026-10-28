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

        public Task SaveAsync(byte[] encryptedVault)
        {
            return SaveInternalAsync(encryptedVault, overwrite: true);
        }

        public Task SaveNewAsync(byte[] encryptedVault)
        {
            return SaveInternalAsync(encryptedVault, overwrite: false);
        }

        private async Task SaveInternalAsync(byte[] encryptedVault, bool overwrite)
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

                try
                {
                    File.Move(tempPath, _filePath, overwrite);
                }
                catch (IOException ex) when (!overwrite && File.Exists(_filePath))
                {
                    throw new InvalidOperationException("A vault already exists.", ex);
                }
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }

        public async Task<byte[]?> LoadAsync()
        {
            if (!File.Exists(_filePath))
                return null;

            await using var stream = new FileStream(
                _filePath, 
                FileMode.Open, 
                FileAccess.Read, 
                FileShare.Read, 
                bufferSize: 8192, 
                useAsync: true);

            if (stream.Length > VaultConstants.MaxVaultFileSize)
                throw new InvalidDataException("Vault file exceeds maximum size.");

            using var memoryStream = new MemoryStream();

            byte[] buffer = new byte[8192];

            while (true)
            {
                int remaining = VaultConstants.MaxVaultFileSize - (int)memoryStream.Length;

                int bytesToRead = Math.Min(buffer.Length, remaining + 1);

                int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, bytesToRead));

                if (bytesRead == 0)
                    break;

                if (bytesRead > remaining)
                    throw new InvalidDataException("Vault file exceeds maximum size.");

                memoryStream.Write(buffer, 0, bytesRead);
            }

            return memoryStream.ToArray();
        }
    }
}
