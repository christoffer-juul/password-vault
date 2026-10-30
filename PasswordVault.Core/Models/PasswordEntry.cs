using System.Text.Json.Serialization;

namespace PasswordVault.Core.Models
{
    public class PasswordEntry
    {
        [JsonRequired]
        public Guid Id { get; init; } = Guid.NewGuid();

        [JsonRequired]
        public string Title { get; init; } = string.Empty;

        public string Username { get; init; } = string.Empty;

        [JsonRequired]
        public string Password { get; init; } = string.Empty;

        public string Url { get; init; } = string.Empty;
    }
}
