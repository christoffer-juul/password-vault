using System.Text.Json.Serialization;

namespace PasswordVault.Core.Models
{
    public class Vault
    {
        private readonly List<PasswordEntry> _entries = [];

        public IReadOnlyList<PasswordEntry> Entries => _entries.AsReadOnly();

        private static void ValidateEntry(PasswordEntry entry)
        {
            ArgumentNullException.ThrowIfNull(entry);

            if (entry.Id == Guid.Empty)
                throw new ArgumentException("Entry ID cannot be empty.", nameof(entry));

            if (string.IsNullOrWhiteSpace(entry.Title))
                throw new ArgumentException("Entry title cannot be empty.");

            if (entry.Password is null)
                throw new ArgumentException("Password cannot be null.");
        }
        
        public void AddEntry(PasswordEntry entry)
        {
            ValidateEntry(entry);

            if (Entries.Any(e => e.Id == entry.Id))
                throw new InvalidOperationException("An entry with the same ID already exists.");

            _entries.Add(entry);
        }

        public void UpdateEntry(PasswordEntry updatedEntry)
        {
            ValidateEntry(updatedEntry);

            int index = _entries.FindIndex(e => e.Id == updatedEntry.Id);

            if (index == -1)
                throw new KeyNotFoundException("Entry not found.");

            _entries[index] = updatedEntry;
        }

        public void RemoveEntry(Guid id)
        {
            int index = _entries.FindIndex(e => e.Id == id);

            if (index == -1)
                throw new KeyNotFoundException("Entry not found.");

            _entries.RemoveAt(index);
        }
    }
}
