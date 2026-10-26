using PasswordVault.Core.Models;

namespace PasswordVault.Core.Interfaces
{
    public interface IVaultFileSerializer
    {
        byte[] Serialize(VaultFile vaultFile);

        VaultFile Deserialize(byte[] data);
    }
}
