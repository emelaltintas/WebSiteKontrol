using System.Text.Json;

namespace WebSiteKontrol.Monitoring;

public sealed class ManagedSiteRegistry
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string _filePath;
    private readonly ILogger<ManagedSiteRegistry> _logger;
    private readonly object _lock = new();

    public ManagedSiteRegistry(IWebHostEnvironment environment, ILogger<ManagedSiteRegistry> logger)
    {
        _logger = logger;
        _filePath = Path.Combine(environment.ContentRootPath, "data", "managed-sites.json");
        EnsureStorage();
    }

    public IReadOnlyList<ManagedSiteEntry> GetAll()
    {
        lock (_lock)
        {
            return LoadUnsafe()
                .OrderBy(x => x.UnitName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.SiteName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Url, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public IReadOnlyList<string> GetUrls()
    {
        return GetAll()
            .Select(x => NormalizeUrl(x.Url))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public ManagedSiteEntry Upsert(ManagedSiteEntry input)
    {
        lock (_lock)
        {
            var sites = LoadUnsafe();
            var normalizedUrl = NormalizeUrl(input.Url);
            if (string.IsNullOrWhiteSpace(normalizedUrl))
            {
                throw new InvalidOperationException("Gecersiz URL");
            }

            var id = string.IsNullOrWhiteSpace(input.Id) ? Guid.NewGuid().ToString("N") : input.Id.Trim();
            var index = sites.FindIndex(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));

            if (index < 0)
            {
                // URL tekil olsun; ayni URL varsa onu guncelle
                index = sites.FindIndex(x => string.Equals(NormalizeUrl(x.Url), normalizedUrl, StringComparison.OrdinalIgnoreCase));
                if (index >= 0)
                {
                    id = sites[index].Id;
                }
            }

            var normalized = new ManagedSiteEntry
            {
                Id = id,
                Url = normalizedUrl,
                GroupKey = NormalizeGroup(input.GroupKey),
                SiteName = input.SiteName?.Trim() ?? "",
                UnitName = input.UnitName?.Trim() ?? "",
                ServerId = input.ServerId?.Trim() ?? "",
                Platform = input.Platform?.Trim() ?? "",
                ResponsibleName = input.ResponsibleName?.Trim() ?? "",
                ResponsibleEmail = input.ResponsibleEmail?.Trim() ?? "",
                ResponsiblePhone = input.ResponsiblePhone?.Trim() ?? "",
                ResponsibleTitle = input.ResponsibleTitle?.Trim() ?? "",
                CreatedAtUtc = index >= 0 ? sites[index].CreatedAtUtc : DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow,
            };

            if (index >= 0)
            {
                sites[index] = normalized;
            }
            else
            {
                sites.Add(normalized);
            }

            SaveUnsafe(sites);
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
            var sites = LoadUnsafe();
            var removed = sites.RemoveAll(x => string.Equals(x.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));
            if (removed <= 0)
            {
                return false;
            }

            SaveUnsafe(sites);
            return true;
        }
    }

    public int RemoveByServerId(string? serverId)
    {
        if (string.IsNullOrWhiteSpace(serverId))
        {
            return 0;
        }

        lock (_lock)
        {
            var sites = LoadUnsafe();
            var removed = sites.RemoveAll(x => string.Equals(x.ServerId, serverId.Trim(), StringComparison.OrdinalIgnoreCase));
            if (removed > 0)
            {
                SaveUnsafe(sites);
            }

            return removed;
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

    private List<ManagedSiteEntry> LoadUnsafe()
    {
        try
        {
            var json = File.ReadAllText(_filePath);
            var list = JsonSerializer.Deserialize<List<ManagedSiteEntry>>(json, JsonOptions) ?? new List<ManagedSiteEntry>();
            var mutated = false;

            foreach (var item in list)
            {
                if (string.IsNullOrWhiteSpace(item.Id))
                {
                    item.Id = Guid.NewGuid().ToString("N");
                    mutated = true;
                }

                if (item.CreatedAtUtc == default)
                {
                    item.CreatedAtUtc = DateTime.UtcNow;
                    mutated = true;
                }

                if (item.UpdatedAtUtc == default)
                {
                    item.UpdatedAtUtc = item.CreatedAtUtc;
                    mutated = true;
                }
            }

            if (mutated)
            {
                SaveUnsafe(list);
            }

            return list;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Site veri dosyasi okunamadi: {Path}", _filePath);
            return new List<ManagedSiteEntry>();
        }
    }

    private void SaveUnsafe(List<ManagedSiteEntry> sites)
    {
        var json = JsonSerializer.Serialize(sites, JsonOptions);
        File.WriteAllText(_filePath, json);
    }

    private static string NormalizeUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var value = raw.Trim();
        if (!value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            value = "https://" + value;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return string.Empty;
        }

        var builder = new UriBuilder(uri)
        {
            Path = string.IsNullOrWhiteSpace(uri.AbsolutePath) ? "/" : uri.AbsolutePath,
        };

        return builder.Uri.ToString().TrimEnd('/');
    }

    private static string NormalizeGroup(string? rawGroup)
    {
        if (string.IsNullOrWhiteSpace(rawGroup))
        {
            return "diger";
        }

        return rawGroup.Trim().ToLowerInvariant();
    }
}
