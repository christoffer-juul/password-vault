using PasswordVault.Core.Constants;
using PasswordVault.Storage;

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
                await storage.SaveAsync(data);

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
                await storage.SaveAsync(data);

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
                await Assert.ThrowsAsync<InvalidDataException>(() => storage.SaveAsync(data));
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
                await storage.SaveAsync(initialData);

                await Assert.ThrowsAsync<InvalidDataException>(() => storage.SaveAsync(newData));

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
                await storage.SaveAsync(initialData);
                await storage.SaveAsync(newData);

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
                Exception? exception = await Record.ExceptionAsync(() => storage.SaveAsync(data));

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
    }
}
