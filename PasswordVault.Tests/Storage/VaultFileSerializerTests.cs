using PasswordVault.Core.Constants;
using PasswordVault.Core.Models;
using PasswordVault.Storage;
using System.Security.Cryptography;
using System.Text;

namespace PasswordVault.Tests.Storage
{
    public class VaultFileSerializerTests
    {
        [Fact]
        public void SerializeThenDeserialize_ReturnsOriginalVaultFile()
        {
            var serializer = new VaultFileSerializer();

            var original = new VaultFile
            {
                Version = VaultConstants.Version,
                KdfAlgorithm = VaultConstants.KdfAlgorithm,
                MemoryKiB = VaultConstants.Argon2MemoryKiB,
                Iterations = VaultConstants.Argon2Iterations,
                Parallelism = VaultConstants.Argon2Parallelism,
                Salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize),
                EncryptedData = new byte[VaultConstants.NonceSize + VaultConstants.TagSize]
            };

            byte[] serialized = serializer.Serialize(original);
            VaultFile deserialized = serializer.Deserialize(serialized);

            Assert.Equal(original.Version, deserialized.Version);
            Assert.Equal(original.KdfAlgorithm, deserialized.KdfAlgorithm);
            Assert.Equal(original.MemoryKiB, deserialized.MemoryKiB);
            Assert.Equal(original.Iterations, deserialized.Iterations);
            Assert.Equal(original.Parallelism, deserialized.Parallelism);
            Assert.Equal(original.Salt, deserialized.Salt);
            Assert.Equal(original.EncryptedData, deserialized.EncryptedData);
        }

        [Fact]
        public void Deserialize_UnsupportedVersion_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            var vaultFile = new VaultFile
            {
                Version = 999, // Unsupported version
                KdfAlgorithm = VaultConstants.KdfAlgorithm,
                MemoryKiB = VaultConstants.Argon2MemoryKiB,
                Iterations = VaultConstants.Argon2Iterations,
                Parallelism = VaultConstants.Argon2Parallelism,
                Salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize),
                EncryptedData = new byte[VaultConstants.NonceSize + VaultConstants.TagSize]
            };

            byte[] serialized = serializer.Serialize(vaultFile);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(serialized));
        }

        [Fact]
        public void Desarialize_InvalidSaltLength_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            var vaultFile = new VaultFile
            {
                Version = VaultConstants.Version,
                KdfAlgorithm = VaultConstants.KdfAlgorithm,
                MemoryKiB = VaultConstants.Argon2MemoryKiB,
                Iterations = VaultConstants.Argon2Iterations,
                Parallelism = VaultConstants.Argon2Parallelism,
                Salt = RandomNumberGenerator.GetBytes(32), // Invalid salt length, should be 16 bytes.
                EncryptedData = new byte[VaultConstants.NonceSize + VaultConstants.TagSize]
            };

            byte[] serialized = serializer.Serialize(vaultFile);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(serialized));
        }

        [Fact]
        public void Deserialize_UnsupportedKdfAlgorithm_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            var vaultFile = new VaultFile
            {
                Version = VaultConstants.Version,
                KdfAlgorithm = "Unknown",
                MemoryKiB = VaultConstants.Argon2MemoryKiB,
                Iterations = VaultConstants.Argon2Iterations,
                Parallelism = VaultConstants.Argon2Parallelism,
                Salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize),
                EncryptedData = new byte[VaultConstants.NonceSize + VaultConstants.TagSize]
            };

            byte[] serialized = serializer.Serialize(vaultFile);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(serialized));
        }

        [Theory]
        [InlineData(8192, 2, 1)] // Wrong memorysize
        [InlineData(19456, 1, 1)] // Wrong iterations
        [InlineData(19456, 2, 4)] // Wrong parallelism
        public void Deserialize_InvalidArgon2Parameters_ThrowsInvalidDataException(int memoryKiB, int iterations, int parallelism)
        {
            var serializer = new VaultFileSerializer();

            var vaultFile = new VaultFile
            {
                Version = VaultConstants.Version,
                KdfAlgorithm = VaultConstants.KdfAlgorithm,
                MemoryKiB = memoryKiB,
                Iterations = iterations,
                Parallelism = parallelism,
                Salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize),
                EncryptedData = new byte[VaultConstants.NonceSize + VaultConstants.TagSize]
            };

            byte[] serialized = serializer.Serialize(vaultFile);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(serialized));
        }

        [Fact]
        public void Deserialize_CorruptedJson_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            byte[] corruptedData = Encoding.UTF8.GetBytes("{ \"Version\": 1,"); // Incomplete JSON

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(corruptedData));
        }

        [Fact]
        public void Deserialize_MissingKdfAlgorithm_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            string json = """
                {
                    "Version": 1,
                    "MemoryKiB": 19456,
                    "Iterations": 2,
                    "Parallelism": 1,
                    "Salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "EncryptedData": "AQIDBAU="
                }
                """;

            byte[] data = Encoding.UTF8.GetBytes(json);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_MissingVersion_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            string json = """
                {
                    "KdfAlgorithm": "Argon2id",
                    "MemoryKiB": 19456,
                    "Iterations": 2,
                    "Parallelism": 1,
                    "Salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "EncryptedData": "AQIDBAU="
                }
                """;

            byte[] data = Encoding.UTF8.GetBytes(json);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_InvalidEncryptedData_ThrowsInvalidDataException()
        {
            var serializer = new VaultFileSerializer();

            var vaultFile = new VaultFile
            {
                Version = VaultConstants.Version,
                KdfAlgorithm = VaultConstants.KdfAlgorithm,
                MemoryKiB = VaultConstants.Argon2MemoryKiB,
                Iterations = VaultConstants.Argon2Iterations,
                Parallelism = VaultConstants.Argon2Parallelism,
                Salt = RandomNumberGenerator.GetBytes(VaultConstants.SaltSize),
                EncryptedData = [10, 20, 30, 40, 50] // Too short to include nonce and tag.
            };

            byte[] serialized = serializer.Serialize(vaultFile);

            Assert.Throws<InvalidDataException>(() => serializer.Deserialize(serialized));
        }
    }
}
