namespace PasswordVault.Core.Interfaces
{
    public interface IVaultStorage
    {
        Task SaveAsync(byte[] encryptedVault);
        Task<byte[]?> LoadAsync();
    }
}
