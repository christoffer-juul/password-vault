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
    }
}
