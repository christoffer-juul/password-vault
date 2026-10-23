namespace PasswordVault.Core.Interfaces
{
    public interface IKeyDerivationService
    {
        Task<byte[]> DeriveKeyAsync(string password, byte[] salt);
    }
}
