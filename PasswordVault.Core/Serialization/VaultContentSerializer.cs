using PasswordVault.Core.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PasswordVault.Core.Serialization
{
    public static class VaultContentSerializer
    {
        private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

        private sealed class VaultContentData
        {
            [JsonRequired]
            public List <PasswordEntry>? Entries { get; set; }
        }

        public static byte[] Serialize(Vault vault)
        {
            ArgumentNullException.ThrowIfNull(vault);

            var data = new VaultContentData { Entries = vault.Entries.ToList() };

            return JsonSerializer.SerializeToUtf8Bytes(data, Options);
        }

        public static Vault Deserialize(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            try
            {
                VaultContentData deserialized = JsonSerializer.Deserialize<VaultContentData>(data, Options)
                    ?? throw new InvalidDataException("Could not deserialize vault content.");

                if (deserialized.Entries is null)
                    throw new InvalidDataException("Vault content is missing entries.");

                var vault = new Vault();

                foreach (PasswordEntry entry in deserialized.Entries)
                {
                    try
                    {
                        vault.AddEntry(entry);
                    }
                    catch (ArgumentException ex)
                    {
                        throw new InvalidDataException("Invalid password entry.", ex);
                    }
                    catch (InvalidOperationException ex)
                    {
                        throw new InvalidDataException("Duplicate password entry ID.", ex);
                    }
                }

                return vault;
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Invalid vault content JSON.", ex);
            }
        }
    }
}
