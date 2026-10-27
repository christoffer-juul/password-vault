using PasswordVault.Core.Constants;
using PasswordVault.Core.Models;
using PasswordVault.Core.Serialization;

namespace PasswordVault.Tests.Serialization
{
    public class VaultMetadataSerializerTests
    {
        [Fact]
        public void Serialize_SameMetadata_ReturnsSameBytes()
        {
            byte[] salt = new byte[VaultConstants.SaltSize];

            var firstVault = new VaultFile { Salt = salt };
            var secondVault = new VaultFile { Salt = salt.ToArray() };

            byte[] firstAad = VaultMetadataSerializer.Serialize(firstVault);
            byte[] secondAad = VaultMetadataSerializer.Serialize(secondVault);

            Assert.Equal(firstAad, secondAad);
        }

        [Fact]
        public void Serialize_DifferentSalt_ReturnsDifferentBytes()
        {
            byte[] firstSalt = new byte[VaultConstants.SaltSize];
            byte[] secondSalt = new byte[VaultConstants.SaltSize];

            secondSalt[0] = 1; // Change the first byte of the second salt

            var firstVault = new VaultFile { Salt = firstSalt };
            var secondVault = new VaultFile { Salt = secondSalt };

            byte[] firstAad = VaultMetadataSerializer.Serialize(firstVault);
            byte[] secondAad = VaultMetadataSerializer.Serialize(secondVault);

            Assert.NotEqual(firstAad, secondAad);
        }

        [Fact]
        public void Serialize_DifferentIterations_ReturnsDifferentBytes()
        {
            byte[] salt = new byte[VaultConstants.SaltSize];

            var firstVault = new VaultFile { Salt = salt, Iterations = VaultConstants.Argon2Iterations };
            var secondVault = new VaultFile { Salt = salt, Iterations = VaultConstants.Argon2Iterations + 1 };

            byte[] firstAad = VaultMetadataSerializer.Serialize(firstVault);
            byte[] secondAad = VaultMetadataSerializer.Serialize(secondVault);

            Assert.NotEqual(firstVault, secondVault);
        }

        [Fact]
        public void Serialize_KnownMetadata_ReturnsExpectedBytes()
        {
            var vaultFile = new VaultFile
            {
                Version = 2,
                KdfAlgorithm = "Argon2id",
                MemoryKiB = 19456,
                Iterations = 2,
                Parallelism = 1,
                Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray()
            };

            string expectedHex = "1B50617373776F72645661756C743A4D657461646174614141443A3102000000084172676F" +
            "6E326964004C0000020000000100000010000000000102030405060708090A0B0C0D0E0F";

            byte[] expected = Convert.FromHexString(expectedHex);

            byte[] actual = VaultMetadataSerializer.Serialize(vaultFile);

            Assert.Equal(expected, actual);
        }
    }
}
