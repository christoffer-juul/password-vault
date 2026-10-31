using PasswordVault.Core.Models;
using PasswordVault.Core.Serialization;
using System.Text;

namespace PasswordVault.Tests.Serialization
{
    public class VaultContentSerializerTests
    {
        [Fact]
        public void SerializeThenDeserialize_ReturnsOriginalEntries()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = "test@example.com",
                Password = "testar123!",
                Url = "https://example.com"
            };

            vault.AddEntry(entry);

            byte[] serialized = VaultContentSerializer.Serialize(vault);

            Vault deserialized = VaultContentSerializer.Deserialize(serialized);

            Assert.Single(deserialized.Entries);

            PasswordEntry loadedEntry = deserialized.Entries[0];

            Assert.Equal(entry.Id, loadedEntry.Id);
            Assert.Equal(entry.Title, loadedEntry.Title);
            Assert.Equal(entry.Username, loadedEntry.Username);
            Assert.Equal(entry.Password, loadedEntry.Password);
            Assert.Equal(entry.Url, loadedEntry.Url);
        }

        [Fact]
        public void SerializeThenDeserialize_EmptyVault_ReturnsEmptyVault()
        {
            var vault = new Vault();

            byte[] serialized = VaultContentSerializer.Serialize(vault);

            Vault deserialized = VaultContentSerializer.Deserialize(serialized);

            Assert.NotNull(deserialized);
            Assert.Empty(deserialized.Entries);
        }

        [Fact]
        public void Deserialize_CorruptedJson_ThrowsInvalidDataException()
        {
            byte[] corruptedData = Encoding.UTF8.GetBytes("""{"entries":[""");

            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(corruptedData));
        }

        [Fact]
        public void Deserialize_MissingTitle_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("""
                {"entries": [{"id": "11111111-1111-1111-1111-111111111111", "username": "test@example.com", "password": "testar123!", "url": "https://example.com"}
                ]}
                """);

            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_EmptyTitle_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("""
                {"entries": [{"id": "11111111-1111-1111-1111-111111111111", "title": "", "password": "testar123!"}
                ]}
                """);

            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_DuplicateEntryIds_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("""
                {"entries": [
                    {"id": "11111111-1111-1111-1111-111111111111", "title": "Test1", "password": "testar123!"},
                    {"id": "11111111-1111-1111-1111-111111111111", "title": "Test2", "password": "testar123!"}
                ]}
                """);
            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_MissingEntries_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("{}");

            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_EmptyId_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("""
                {"entries": [
                    {"id": "00000000-0000-0000-0000-000000000000", "title": "Test1", "password": "testar123!"}
                ]}
                """);

            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_MissingId_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("""
                {"entries": [
                    {"title": "Test1", "password": "testar123!"}
                ]}
                """);
            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_PasswordNull_ThrowsInvalidDataException()
        {
            byte[] data = Encoding.UTF8.GetBytes("""
                {"entries": [
                    {"id": "11111111-1111-1111-1111-111111111111", "title": "Test1", "password": null}
                ]}
                """);
            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }

        [Fact]
        public void Deserialize_NullUsername_ThrowsInvalidDataException()
        {
            string json = $$"""
                {
                    "entries": [
                        {
                        "id": "{{Guid.NewGuid()}}",
                        "title": "Test",
                        "username": null,
                        "password": "testar123!",
                        "url": ""
                        }
                    ]
                }
                """;

            byte[] data = Encoding.UTF8.GetBytes(json);

            Assert.Throws<InvalidDataException>(() => VaultContentSerializer.Deserialize(data));
        }
    }
}
