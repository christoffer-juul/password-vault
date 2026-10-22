namespace PasswordVault.Core.Interfaces
{
    public interface IEncryptionService
    {
        byte[] Encrypt(byte[] plainText, byte[] key);
        byte[] Decrypt(byte[] encryptedData, byte[] key);
    }
}
