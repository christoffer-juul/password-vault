namespace PasswordVault.Core.Constants;
public static class VaultConstants
{
    public const int Version = 1;
    public const string KdfAlgorithm = "Argon2id";
    public const int SaltSize = 16;
    public const int KeySize = 32;
    public const int Argon2MemoryKiB = 19456;
    public const int Argon2Iterations = 2;
    public const int Argon2Parallelism = 1;
    public const int NonceSize = 12;
    public const int TagSize = 16;
}