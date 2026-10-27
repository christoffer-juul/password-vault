using PasswordVault.Core.Models;
using System.Text;

namespace PasswordVault.Core.Serialization
{
    public static class VaultMetadataSerializer
    {
        public static byte[] Serialize(VaultFile vaultFile)
        {
            ArgumentNullException.ThrowIfNull(vaultFile);

            using var stream = new MemoryStream();

            using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write("PasswordVault:MetadataAAD:1");

                writer.Write(vaultFile.Version);
                writer.Write(vaultFile.KdfAlgorithm);
                writer.Write(vaultFile.MemoryKiB);
                writer.Write(vaultFile.Iterations);
                writer.Write(vaultFile.Parallelism);
                writer.Write(vaultFile.Salt.Length);
                writer.Write(vaultFile.Salt);
            }

            return stream.ToArray();
        }
    }
}
