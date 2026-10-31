using PasswordVault.Core.Models;

namespace PasswordVault.Tests.Models
{
    public class VaultTests
    {
        [Fact]
        public void AddEntry_ValidEntry_AddsEntryToVault()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = "test@example.com",
                Password = "testar123",
                Url = "https://example.com"
            };

            vault.AddEntry(entry);

            Assert.Single(vault.Entries);
            Assert.Equal(entry, vault.Entries[0]);
        }

        [Fact]
        public void AddEntry_DuplicateId_ThrowsInvalidOperationException()
        {
            var vault = new Vault();

            Guid id = Guid.NewGuid();

            var firstEntry = new PasswordEntry
            {
                Id = id,
                Title = "Test1",
                Username = "test@example.com",
                Password = "testar123"
            };

            var secondEntry = new PasswordEntry
            {
                Id = id,
                Title = "Test2",
                Username = "test@example.com",
                Password = "testar123"
            };

            vault.AddEntry(firstEntry);

            Assert.Throws<InvalidOperationException>(() => vault.AddEntry(secondEntry));
            Assert.Single(vault.Entries);
        }

        [Fact]
        public void AddEntry_NullEntry_ThrowsArgumentNullException()
        {
            var vault = new Vault();

            Assert.Throws<ArgumentNullException>(() => vault.AddEntry(null!));
            Assert.Empty(vault.Entries);
        }

        [Fact]
        public void Entries_CannotBeModifiedDirectly()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = "test@example.com",
                Password = "testar123"
            };

            Assert.Throws<NotSupportedException>(() => ((IList<PasswordEntry>)vault.Entries).Add(entry));
        }

        [Fact]
        public void UpdateEntry_ExistingId_UpdatesEntry()
        {
            var vault = new Vault();

            var originalEntry = new PasswordEntry
            {
                Title = "Test",
                Username = "test@example.com",
                Password = "testar123"
            };

            vault.AddEntry(originalEntry);

            var updatedEntry = new PasswordEntry
            {
                Id = originalEntry.Id,
                Title = "Updated Test",
                Username = "updated@example.com",
                Password = "updated123",
            };

            vault.UpdateEntry(updatedEntry);

            Assert.Single(vault.Entries);

            PasswordEntry savedEntry = vault.Entries[0];

            Assert.Equal(originalEntry.Id, savedEntry.Id);
            Assert.Equal("updated@example.com", savedEntry.Username);
            Assert.Equal("updated123", savedEntry.Password);
        }

        [Fact]
        public void UpdateEntry_UnknownId_ThrowsKeyNotFoundException()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Password = "testar123"
            };

            Assert.Throws<KeyNotFoundException>(() => vault.UpdateEntry(entry));
            Assert.Empty(vault.Entries);
        }

        [Fact]
        public void RemoveEntry_ExistingId_RemovesEntry()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = "test@example.com",
                Password = "testar123",
                Url = "https://example.com"
            };

            vault.AddEntry(entry);

            vault.RemoveEntry(entry.Id);

            Assert.Empty(vault.Entries);
        }

        [Fact]
        public void RemoveEntry_UnknownId_ThrowsKeyNotFoundException()
        {
            var vault = new Vault();

            Guid unknownId = Guid.NewGuid();

            Assert.Throws<KeyNotFoundException>(() => vault.RemoveEntry(unknownId));

            Assert.Empty(vault.Entries);
        }

        [Fact]
        public void RemoveEntry_MultipleEntries_RemovesOnlyMatchingEntry()
        {
            var vault = new Vault();

            var githubEntry = new PasswordEntry
            {
                Title = "Github",
                Password = "testar123!"
            };

            var discordEntry = new PasswordEntry
            {
                Title = "Discord",
                Password = "testar456!"
            };

            vault.AddEntry(githubEntry);
            vault.AddEntry(discordEntry);

            vault.RemoveEntry(githubEntry.Id);

            Assert.Single(vault.Entries);
            Assert.Equal(discordEntry.Id, vault.Entries[0].Id);
        }

        [Fact]
        public void AddEntry_NullUsername_ThrowsArgumentException()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = null!,
                Password = "testar123!"
            };

            Assert.Throws<ArgumentException>(() => vault.AddEntry(entry));

            Assert.Empty(vault.Entries);
        }

        [Fact]
        public void AddEntry_NullUrl_ThrowsArgumentException()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = "test@example.com",
                Password = "testar123!",
                Url = null!
            };

            Assert.Throws<ArgumentException>(() => vault.AddEntry(entry));

            Assert.Empty(vault.Entries);
        }

        [Fact]
        public void AddEntry_EmptyOptionalFields_AddsEntry()
        {
            var vault = new Vault();

            var entry = new PasswordEntry
            {
                Title = "Test",
                Username = "",
                Password = "testar123!",
                Url = ""
            };

            vault.AddEntry(entry);

            Assert.Single(vault.Entries);
            Assert.Equal(entry.Id, vault.Entries[0].Id);
        }
    }
}
