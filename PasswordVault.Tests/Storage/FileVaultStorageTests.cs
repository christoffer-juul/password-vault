using PasswordVault.Core.Constants;
using PasswordVault.Core.Exceptions;
using PasswordVault.Storage;
using System.Security.Cryptography;

namespace PasswordVault.Tests.Storage
{
    public class FileVaultStorageTests
    {
        [Fact]
        public async Task SaveAsync_ValidData_CreatesFile()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] data = [10, 20, 30, 40, 50];

            try
            {
                await storage.SaveNewAsync(data);

                Assert.True(File.Exists(filePath));
            }
            finally
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        }

        [Fact]
        public async Task LoadAsync_ExistingFile_ReturnsSavedData()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] data = [10, 20, 30, 40, 50];

            try
            {
                await storage.SaveNewAsync(data);

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(data, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        }

        [Fact]
        public async Task LoadAsync_FileDoesNotExist_ReturnsNull()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[]? result = await storage.LoadAsync();

            Assert.Null(result);
        }

        [Fact]
        public async Task SaveAsync_FileTooLarge_ThrowsInvalidDataException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] data = new byte[VaultConstants.MaxVaultFileSize + 1];

            try
            {
                await Assert.ThrowsAsync<InvalidDataException>(() => storage.SaveNewAsync(data));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task LoadAsync_FileTooLarge_ThrowsInvalidDataException()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            Directory.CreateDirectory(directory);

            byte[] data = new byte[VaultConstants.MaxVaultFileSize + 1];

            try
            {
                await File.WriteAllBytesAsync(filePath, data);

                var storage = new FileVaultStorage(filePath);

                await Assert.ThrowsAsync<InvalidDataException>(() => storage.LoadAsync());
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveAsync_FileTooLarge_PreservesExistingFiles()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] initialData = [10, 20, 30, 40, 50];

            byte[] newData = new byte[VaultConstants.MaxVaultFileSize + 1];

            try
            {
                await storage.SaveNewAsync(initialData);

                string expectedVersion = Convert.ToHexString(SHA256.HashData(initialData));

                await Assert.ThrowsAsync<InvalidDataException>(() => storage.SaveAsync(newData, expectedVersion));

                Assert.True(File.Exists(filePath));

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(initialData, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveAsync_ExistingFile_ReplacesContents()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] initialData = [10, 20, 30];

            byte[] newData = [40, 50, 60];

            try
            {
                await storage.SaveNewAsync(initialData);

                string expectedVersion = Convert.ToHexString(SHA256.HashData(initialData));


                await storage.SaveAsync(newData, expectedVersion);

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(newData, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task LoadAsync_FileAtMaxSize_ReturnsSavedData()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            Directory.CreateDirectory(directory);

            byte[] data = new byte[VaultConstants.MaxVaultFileSize];

            try
            {
                await File.WriteAllBytesAsync(filePath, data);

                var storage = new FileVaultStorage(filePath);

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(data, loadedData);
            }
            finally
            {
                if(Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveAsync_FailedMove_DeletesTemporaryFile()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            Directory.CreateDirectory(directory);

            Directory.CreateDirectory(filePath); // Create a directory with the same name to cause a move failure

            var storage = new FileVaultStorage(filePath);

            byte[] data = [10, 20, 30, 40, 50];

            try
            {
                Exception? exception = await Record.ExceptionAsync(() => storage.SaveNewAsync(data));

                Assert.NotNull(exception);

                Assert.True(exception is IOException or UnauthorizedAccessException);

                string[] tempFiles = Directory.GetFiles(directory, "vault.dat.*.tmp");

                Assert.Empty(tempFiles);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveNewAsync_FileDoesNotExist_CreatesFile()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] data = [10, 20, 30, 40, 50];

            try
            {
                await storage.SaveNewAsync(data);

                Assert.True(File.Exists(filePath));

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(data, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveNewAsync_DoesNotOverwrite_ExistingFile()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] originalData = [10, 20, 30];
            byte[] newData = [40, 50, 60];

            try
            {
                await storage.SaveNewAsync(originalData);

                await Assert.ThrowsAsync<InvalidOperationException>(() => storage.SaveNewAsync(newData));

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(originalData, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveNewAsync_ConcurrentCalls_OnlyOneSucceeds()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] firstData = [10, 20, 30];
            byte[] secondData = [40, 50, 60];

            try
            {
                Task<Exception?> first = Record.ExceptionAsync(() => storage.SaveNewAsync(firstData));
                Task<Exception?> second = Record.ExceptionAsync(() => storage.SaveNewAsync(secondData));

                Exception?[] results = await Task.WhenAll(first, second);

                // Only one of the calls should succeed, the other should throw an InvalidOperationException
                Assert.Single(results, ex => ex is null);
                Assert.Single(results, ex => ex is InvalidOperationException);

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);

                bool matchesFirst = loadedData.SequenceEqual(firstData);
                bool matchesSecond = loadedData.SequenceEqual(secondData);

                Assert.True(matchesFirst || matchesSecond);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveAsync_StaleVersion_DoesNotOverwriteFile()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] originalData = [1, 2, 3];
            byte[] updatedData = [4, 5, 6];
            byte[] staleData = [7, 8, 9];

            try
            {
                await storage.SaveNewAsync(originalData);

                string originalVersion = Convert.ToHexString(SHA256.HashData(originalData));

                await storage.SaveAsync(updatedData, originalVersion);

                await Assert.ThrowsAsync<VaultConflictException>(() => storage.SaveAsync(staleData, originalVersion));

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(updatedData, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveAsync_MatchingVersion_UpdatesFile()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storage = new FileVaultStorage(filePath);

            byte[] originalData = [1, 2, 3];
            byte[] updatedData = [4, 5, 6];

            try
            {
                await storage.SaveNewAsync(originalData);

                string expectedVersion = Convert.ToHexString(SHA256.HashData(originalData));

                await storage.SaveAsync(updatedData, expectedVersion);

                byte[]? loadedData = await storage.LoadAsync();

                Assert.NotNull(loadedData);
                Assert.Equal(updatedData, loadedData);
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public async Task SaveAsync_ConcurrentUpdates_OnlyOneSucceeds()
        {
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            string filePath = Path.Combine(directory, "vault.dat");

            var storageA = new FileVaultStorage(filePath);
            var storageB = new FileVaultStorage(filePath);

            byte[] originalData = [1, 2, 3];
            byte[] dataA = [4, 5, 6];
            byte[] dataB = [7, 8, 9];

            try
            {
                await storageA.SaveNewAsync(originalData);

                string expectedVersion = Convert.ToHexString(SHA256.HashData(originalData));

                Task<Exception?> taskA = Record.ExceptionAsync(() => storageA.SaveAsync(dataA, expectedVersion));

                Task<Exception?> taskB = Record.ExceptionAsync(() => storageB.SaveAsync(dataB, expectedVersion));

                Exception?[] results = await Task.WhenAll(taskA, taskB);

                Assert.Equal(1, results.Count(e => e is null));

                Assert.Equal(1, results.Count(e => e is VaultConflictException));

                byte[]? loadedData = await storageA.LoadAsync();

                Assert.NotNull(loadedData);

                Assert.True(loadedData.SequenceEqual(dataA) || loadedData.SequenceEqual(dataB));
            }
            finally
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
        }
    }
}
