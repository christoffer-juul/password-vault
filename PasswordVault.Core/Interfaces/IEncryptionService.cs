namespace PasswordVault.Core.Interfaces
{
    public interface IEncryptionService
    {
        byte[] Encrypt(byte[] plainText, byte[] key, byte[]? associatedData = null);
        byte[] Decrypt(byte[] encryptedData, byte[] key, byte[]? associatedData = null);
    }
}
