using PasswordVault.Core.Constants;
using PasswordVault.Core.Exceptions;
using PasswordVault.Core.Interfaces;
using System.Security.Cryptography;

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

        public async Task SaveNewAsync(byte[] encryptedVault)
        {
            ArgumentNullException.ThrowIfNull(encryptedVault);

            string directory = Path.GetDirectoryName(_filePath)!;
            Directory.CreateDirectory(directory);

            string lockPath = _filePath + ".lock";

            await using FileStream lockStream = await AcquireLockAsync(lockPath);

            await SaveInternalAsync(encryptedVault, overwrite: false);
        }

        private async Task SaveInternalAsync(byte[] encryptedVault, bool overwrite)
        {
            ArgumentNullException.ThrowIfNull(encryptedVault);

            if (encryptedVault.Length > VaultConstants.MaxVaultFileSize)
                throw new InvalidDataException("Vault file exceeds maximum size.");

            string directory = Path.GetDirectoryName(_filePath)!;

            string tempPath = Path.Combine(directory, $".{Path.GetFileName(_filePath)}.{Guid.NewGuid():N}.tmp");

            try
            {
                await using (var stream = new FileStream(
                    tempPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 8192,
                    useAsync: true))
                {
                    await stream.WriteAsync(encryptedVault.AsMemory());

                    stream.Flush(flushToDisk: true);
                }

                try
                {
                    File.Move(tempPath, _filePath, overwrite);
                }
                catch (IOException ex) when (!overwrite && File.Exists(_filePath))
                {
                    throw new InvalidOperationException(
                        "A vault already exists.", ex);
                }
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }

        public async Task SaveAsync(byte[] encryptedVault, string expectedVersion)
        {
            ArgumentNullException.ThrowIfNull(encryptedVault);
            ArgumentException.ThrowIfNullOrWhiteSpace(expectedVersion);

            if (encryptedVault.Length > VaultConstants.MaxVaultFileSize)
                throw new InvalidDataException("Vault file exceeds maximum size.");

            string directory = Path.GetDirectoryName(_filePath)!;
            Directory.CreateDirectory(directory);

            string lockPath = _filePath + ".lock";

            await using FileStream lockStream = await AcquireLockAsync(lockPath);

            byte[]? currentData = await LoadAsync();

            if (currentData is null)
                throw new InvalidOperationException("Vault file no longer exists.");

            string currentVersion = Convert.ToHexString(SHA256.HashData(currentData));

            if (!string.Equals(currentVersion, expectedVersion, StringComparison.Ordinal))
                throw new VaultConflictException();

            await SaveInternalAsync(encryptedVault, overwrite: true);
        }

        public async Task<byte[]?> LoadAsync()
        {
            if (!File.Exists(_filePath))
                return null;

            await using var stream = new FileStream(
                _filePath, 
                FileMode.Open, 
                FileAccess.Read, 
                FileShare.Read | FileShare.Delete, 
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

        private static async Task<FileStream> AcquireLockAsync(string lockPath)
            {
            const int maxAttempts = 100;
            const int delayMilliseconds = 50;

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                }
                catch (IOException) when (attempt < maxAttempts - 1)
                {
                    await Task.Delay(delayMilliseconds);
                }
            }

            throw new IOException("Could not acquire vault file lock.");
        }
    }
}
