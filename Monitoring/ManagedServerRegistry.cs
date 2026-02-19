using System.Text.Json;

namespace WebSiteKontrol.Monitoring;

public sealed class ManagedServerRegistry
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string _filePath;
    private readonly ILogger<ManagedServerRegistry> _logger;
    private readonly object _lock = new();

    public ManagedServerRegistry(IWebHostEnvironment environment, ILogger<ManagedServerRegistry> logger)
    {
        _logger = logger;
        _filePath = Path.Combine(environment.ContentRootPath, "data", "managed-servers.json");
        EnsureStorage();
    }

    public IReadOnlyList<ManagedServerEntry> GetAll()
    {
        lock (_lock)
        {
            return LoadUnsafe()
                .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.IpAddress, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public ManagedServerEntry Upsert(ManagedServerEntry input)
    {
        lock (_lock)
        {
            var servers = LoadUnsafe();
            var id = string.IsNullOrWhiteSpace(input.Id) ? Guid.NewGuid().ToString("N") : input.Id.Trim();
            var index = servers.FindIndex(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));

            var normalized = new ManagedServerEntry
            {
                Id = id,
                Name = input.Name?.Trim() ?? "",
                IpAddress = input.IpAddress?.Trim() ?? "",
                Username = input.Username?.Trim() ?? "",
                Password = input.Password ?? "",
                Notes = input.Notes?.Trim() ?? "",
                CreatedAtUtc = index >= 0 ? servers[index].CreatedAtUtc : DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow,
            };

            if (index >= 0)
            {
                servers[index] = normalized;
            }
            else
            {
                servers.Add(normalized);
            }

            SaveUnsafe(servers);
            return normalized;
        }
    }

    public bool RemoveById(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return false;
        }

        lock (_lock)
        {
            var servers = LoadUnsafe();
            var removed = servers.RemoveAll(x => string.Equals(x.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));
            if (removed <= 0)
            {
                return false;
            }

            SaveUnsafe(servers);
            return true;
        }
    }

    private void EnsureStorage()
    {
        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (!File.Exists(_filePath))
        {
            File.WriteAllText(_filePath, "[]");
        }
    }

    private List<ManagedServerEntry> LoadUnsafe()
    {
        try
        {
            var json = File.ReadAllText(_filePath);
            return JsonSerializer.Deserialize<List<ManagedServerEntry>>(json, JsonOptions) ?? new List<ManagedServerEntry>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Sunucu veri dosyasi okunamadi: {Path}", _filePath);
            return new List<ManagedServerEntry>();
        }
    }

    private void SaveUnsafe(List<ManagedServerEntry> servers)
    {
        var json = JsonSerializer.Serialize(servers, JsonOptions);
        File.WriteAllText(_filePath, json);
    }
}
