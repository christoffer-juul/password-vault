namespace PasswordVault.Core.Interfaces
{
    public interface IVaultStorage
    {
        Task SaveNewAsync(byte[] encryptedVault);
        Task SaveAsync(byte[] encryptedVault, string expectedVersion);
        Task<byte[]?> LoadAsync();
    }
}
