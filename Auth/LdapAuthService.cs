using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.Extensions.Options;

namespace WebSiteKontrol.Auth;

public sealed class LdapAuthService : ILdapAuthService
{
    private readonly LdapOptions _options;
    private readonly ILogger<LdapAuthService> _logger;

    public LdapAuthService(IOptions<LdapOptions> options, ILogger<LdapAuthService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public Task<LdapAuthResult> AuthenticateAsync(string usernameOrEmail, string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(usernameOrEmail) || string.IsNullOrWhiteSpace(password))
        {
            return Task.FromResult(new LdapAuthResult(false, null));
        }

        try
        {
            var loginInput = usernameOrEmail.Trim();
            var username = GetUsername(loginInput);
            var ldapIdentifier = new LdapDirectoryIdentifier(_options.Server, _options.Port);
            var bindCandidates = BuildBindCandidates(loginInput, username);
            var authTypes = ResolveAuthTypeCandidates(_options.AuthType);
            LdapConnection? boundConnection = null;
            Exception? lastBindException = null;

            foreach (var authType in authTypes)
            {
                foreach (var bindIdentity in bindCandidates)
                {
                    try
                    {
                        var connection = new LdapConnection(ldapIdentifier)
                        {
                            AuthType = authType,
                            Timeout = TimeSpan.FromSeconds(Math.Max(3, _options.TimeoutSeconds)),
                            Credential = new NetworkCredential(bindIdentity, password),
                        };

                        connection.SessionOptions.ProtocolVersion = 3;
                        if (_options.UseSsl)
                        {
                            connection.SessionOptions.SecureSocketLayer = true;
                        }

                        connection.Bind();
                        boundConnection = connection;
                        _logger.LogInformation("LDAP bind basarili. AuthType: {AuthType}, Identity: {Identity}", authType, bindIdentity);
                        break;
                    }
                    catch (Exception ex)
                    {
                        lastBindException = ex;
                        _logger.LogDebug(ex, "LDAP bind denemesi basarisiz. AuthType: {AuthType}, Identity: {Identity}", authType, bindIdentity);
                    }
                }

                if (boundConnection is not null)
                {
                    break;
                }
            }

            if (boundConnection is null)
            {
                if (lastBindException is LdapException ldapEx)
                {
                    _logger.LogWarning(ldapEx, "LDAP giris basarisiz oldu. Sunucu: {Server}", _options.Server);
                }
                else if (lastBindException is not null)
                {
                    _logger.LogError(lastBindException, "LDAP bind sirasinda beklenmeyen hata.");
                }

                return Task.FromResult(new LdapAuthResult(false, null));
            }

            using var connectionInUse = boundConnection;

            var escapedUsername = EscapeFilterValue(username);
            var escapedLoginInput = EscapeFilterValue(loginInput);
            var filter =
                $"(|(sAMAccountName={escapedUsername})(userPrincipalName={escapedLoginInput})(mail={escapedLoginInput}))";

            var request = new SearchRequest(
                _options.BaseDn,
                filter,
                SearchScope.Subtree,
                new[] { "sAMAccountName", "displayName", "givenName", "sn", "mail" });

            var response = (SearchResponse)connectionInUse.SendRequest(request);
            if (response.Entries.Count == 0)
            {
                _logger.LogWarning("LDAP bind basarili fakat kullanici dizinde bulunamadi. LoginInput: {LoginInput}", loginInput);
                return Task.FromResult(new LdapAuthResult(false, null));
            }

            var entry = response.Entries[0];
            var adUsername = GetAttribute(entry, "sAMAccountName") ?? username;
            var displayName =
                GetAttribute(entry, "displayName")
                ?? $"{GetAttribute(entry, "givenName")} {GetAttribute(entry, "sn")}".Trim()
                ?? adUsername;
            var email = GetAttribute(entry, "mail");

            return Task.FromResult(new LdapAuthResult(
                true,
                new LdapUser(adUsername, string.IsNullOrWhiteSpace(displayName) ? adUsername : displayName, email)));
        }
        catch (LdapException ex)
        {
            _logger.LogWarning(ex, "LDAP giris basarisiz oldu. Sunucu: {Server}", _options.Server);
            return Task.FromResult(new LdapAuthResult(false, null));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP islemi sirasinda beklenmeyen hata.");
            return Task.FromResult(new LdapAuthResult(false, null));
        }
    }

    private IReadOnlyList<string> BuildBindCandidates(string loginInput, string username)
    {
        var candidates = new List<string>();

        // ADHelper ile uyumlu: domain\\username ilk tercih.
        if (!string.IsNullOrWhiteSpace(_options.Domain))
        {
            candidates.Add($"{_options.Domain}\\{username}");
        }

        if (!string.IsNullOrWhiteSpace(_options.UpnSuffix))
        {
            candidates.Add($"{username}@{_options.UpnSuffix}");
        }

        if (!string.IsNullOrWhiteSpace(loginInput))
        {
            candidates.Add(loginInput);
        }

        if (!string.IsNullOrWhiteSpace(username))
        {
            candidates.Add(username);
        }

        return candidates
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string GetUsername(string loginInput)
    {
        var atIndex = loginInput.IndexOf('@');
        return atIndex > 0 ? loginInput[..atIndex] : loginInput;
    }

    private static string? GetAttribute(SearchResultEntry entry, string attribute)
    {
        if (!entry.Attributes.Contains(attribute))
        {
            return null;
        }

        var values = entry.Attributes[attribute];
        if (values is null || values.Count == 0)
        {
            return null;
        }

        return values[0]?.ToString();
    }

    private static IReadOnlyList<AuthType> ResolveAuthTypeCandidates(string authType)
    {
        if (authType.Equals("basic", StringComparison.OrdinalIgnoreCase))
        {
            return new[] { AuthType.Basic, AuthType.Negotiate };
        }

        return new[] { AuthType.Negotiate, AuthType.Basic };
    }

    private static string EscapeFilterValue(string value) =>
        value
            .Replace(@"\", @"\5c", StringComparison.Ordinal)
            .Replace("*", @"\2a", StringComparison.Ordinal)
            .Replace("(", @"\28", StringComparison.Ordinal)
            .Replace(")", @"\29", StringComparison.Ordinal)
            .Replace("\u0000", @"\00", StringComparison.Ordinal);
}
