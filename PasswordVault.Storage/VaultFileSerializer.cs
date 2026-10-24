using PasswordVault.Core.Constants;
using PasswordVault.Core.Models;
using System.Text.Json;

namespace PasswordVault.Storage
{
    public class VaultFileSerializer
    {
        public byte[] Serialize(VaultFile vaultFile)
        {
            ArgumentNullException.ThrowIfNull(vaultFile);

            return JsonSerializer.SerializeToUtf8Bytes(vaultFile);
        }

        public VaultFile Deserialize(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            VaultFile vaultFile;

            try
            {
                vaultFile = JsonSerializer.Deserialize<VaultFile>(data)
                ?? throw new InvalidDataException("Failed to deserialize vault file.");
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid vault file JSON.", ex);
            }

            ValidateVaultFile(vaultFile);

            return vaultFile;
        }

        private static void ValidateVaultFile(VaultFile vaultFile)
        {
            if (vaultFile.Version != VaultConstants.Version)
                throw new InvalidDataException(
                    $"Unsupported vault version: {vaultFile.Version}.");

            if (vaultFile.Salt is null || vaultFile.Salt.Length != VaultConstants.SaltSize)
                throw new InvalidDataException("Invalid salt length.");

            if (vaultFile.KdfAlgorithm != VaultConstants.KdfAlgorithm)
                throw new InvalidDataException(
                    $"Unsupported KDF algorithm: {vaultFile.KdfAlgorithm}");

            if (vaultFile.MemoryKiB != VaultConstants.Argon2MemoryKiB ||
                vaultFile.Iterations != VaultConstants.Argon2Iterations ||
                vaultFile.Parallelism != VaultConstants.Argon2Parallelism)
                throw new InvalidDataException(
                    "Unsupported Argon2id parameters.");

            if (vaultFile.EncryptedData is null || vaultFile.EncryptedData.Length < 28)
                throw new InvalidDataException("Invalid encrypted data.");
        }
    }
}
