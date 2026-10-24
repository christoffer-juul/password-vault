using System.Text.Json.Serialization;
using PasswordVault.Core.Constants;

namespace PasswordVault.Core.Models
{
    public sealed class VaultFile
    {
        [JsonRequired]
        public int Version { get; init; } = VaultConstants.Version;

        [JsonRequired]
        public string KdfAlgorithm { get; init; } = VaultConstants.KdfAlgorithm;

        [JsonRequired]
        public int MemoryKiB { get; init; } = VaultConstants.Argon2MemoryKiB;

        [JsonRequired]
        public int Iterations { get; init; } = VaultConstants.Argon2Iterations;

        [JsonRequired]
        public int Parallelism { get; init; } = VaultConstants.Argon2Parallelism;

        [JsonRequired]
        public byte[] Salt { get; init; } = [];

        [JsonRequired]
        public byte[] EncryptedData { get; init; } = [];
    }
}
