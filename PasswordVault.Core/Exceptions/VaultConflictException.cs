namespace PasswordVault.Core.Exceptions
{
    public class VaultConflictException : InvalidOperationException
    {
        public VaultConflictException() : base("Vault has been modified since it was last opened")
        {

        }
    }
}
