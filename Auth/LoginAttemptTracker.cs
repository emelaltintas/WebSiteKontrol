using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace WebSiteKontrol.Auth;

public sealed class LoginAttemptTracker
{
    private readonly ConcurrentDictionary<string, AttemptState> _states = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<LoginAttemptLog> _logs = new();
    private readonly IOptionsMonitor<LoginSecurityOptions> _options;

    public LoginAttemptTracker(IOptionsMonitor<LoginSecurityOptions> options)
    {
        _options = options;
    }

    public bool IsLocked(string loginInput, string clientIp, out TimeSpan remaining)
    {
        var options = _options.CurrentValue;
        var key = BuildKey(loginInput, clientIp);
        remaining = TimeSpan.Zero;

        if (!_states.TryGetValue(key, out var state))
        {
            return false;
        }

        var now = DateTime.UtcNow;
        if (state.LockedUntilUtc.HasValue && state.LockedUntilUtc.Value > now)
        {
            remaining = state.LockedUntilUtc.Value - now;
            return true;
        }

        return false;
    }

    public void RegisterFailure(string loginInput, string clientIp, string reason)
    {
        var options = _options.CurrentValue;
        var key = BuildKey(loginInput, clientIp);
        var now = DateTime.UtcNow;
        var window = TimeSpan.FromMinutes(Math.Max(1, options.AttemptWindowMinutes));
        var lockout = TimeSpan.FromMinutes(Math.Max(1, options.LockoutMinutes));
        var maxFails = Math.Max(1, options.MaxFailedAttempts);

        var state = _states.AddOrUpdate(
            key,
            _ => new AttemptState
            {
                FirstFailureUtc = now,
                LastFailureUtc = now,
                FailureCount = 1,
            },
            (_, current) =>
            {
                if (now - current.FirstFailureUtc > window)
                {
                    current.FirstFailureUtc = now;
                    current.FailureCount = 1;
                }
                else
                {
                    current.FailureCount += 1;
                }

                current.LastFailureUtc = now;
                if (current.FailureCount >= maxFails)
                {
                    current.LockedUntilUtc = now.Add(lockout);
                }

                return current;
            });

        AddLog(new LoginAttemptLog
        {
            AtUtc = now,
            LoginInput = loginInput,
            ClientIp = clientIp,
            Success = false,
            Reason = reason,
            IsLocked = state.LockedUntilUtc.HasValue && state.LockedUntilUtc.Value > now,
        });

        Prune();
    }

    public void RegisterSuccess(string loginInput, string clientIp)
    {
        var key = BuildKey(loginInput, clientIp);
        _states.TryRemove(key, out _);

        AddLog(new LoginAttemptLog
        {
            AtUtc = DateTime.UtcNow,
            LoginInput = loginInput,
            ClientIp = clientIp,
            Success = true,
            Reason = "ok",
            IsLocked = false,
        });

        Prune();
    }

    public IReadOnlyList<LoginAttemptLog> GetRecent(int take = 100)
    {
        var count = Math.Clamp(take, 1, 500);
        return _logs
            .ToArray()
            .OrderByDescending(x => x.AtUtc)
            .Take(count)
            .ToList();
    }

    private void AddLog(LoginAttemptLog entry)
    {
        _logs.Enqueue(entry);
    }

    private void Prune()
    {
        var options = _options.CurrentValue;
        var keepUntil = DateTime.UtcNow.AddMinutes(-Math.Max(1, options.LogRetentionMinutes));

        while (_logs.TryPeek(out var entry) && entry.AtUtc < keepUntil)
        {
            _logs.TryDequeue(out _);
        }

        var maxLogs = 2000;
        while (_logs.Count > maxLogs)
        {
            _logs.TryDequeue(out _);
        }
    }

    private static string BuildKey(string loginInput, string clientIp)
    {
        var login = (loginInput ?? string.Empty).Trim().ToLowerInvariant();
        var ip = (clientIp ?? string.Empty).Trim();
        return $"{login}|{ip}";
    }

    private sealed class AttemptState
    {
        public DateTime FirstFailureUtc { get; set; }
        public DateTime LastFailureUtc { get; set; }
        public int FailureCount { get; set; }
        public DateTime? LockedUntilUtc { get; set; }
    }
}

public sealed class LoginAttemptLog
{
    public DateTime AtUtc { get; set; }
    public string LoginInput { get; set; } = "";
    public string ClientIp { get; set; } = "";
    public bool Success { get; set; }
    public string Reason { get; set; } = "";
    public bool IsLocked { get; set; }
}
