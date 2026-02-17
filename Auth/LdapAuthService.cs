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
            var bindIdentity = BuildBindIdentity(loginInput, username);
            var ldapIdentifier = new LdapDirectoryIdentifier(_options.Server, _options.Port);

            using var connection = new LdapConnection(ldapIdentifier)
            {
                AuthType = ResolveAuthType(_options.AuthType),
                Timeout = TimeSpan.FromSeconds(Math.Max(3, _options.TimeoutSeconds)),
                Credential = new NetworkCredential(bindIdentity, password),
            };

            connection.SessionOptions.ProtocolVersion = 3;
            if (_options.UseSsl)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }

            connection.Bind();

            var escapedUsername = EscapeFilterValue(username);
            var escapedLoginInput = EscapeFilterValue(loginInput);
            var filter =
                $"(|(sAMAccountName={escapedUsername})(userPrincipalName={escapedLoginInput})(mail={escapedLoginInput}))";

            var request = new SearchRequest(
                _options.BaseDn,
                filter,
                SearchScope.Subtree,
                new[] { "sAMAccountName", "displayName", "givenName", "sn", "mail" });

            var response = (SearchResponse)connection.SendRequest(request);
            if (response.Entries.Count == 0)
            {
                return Task.FromResult(new LdapAuthResult(
                    true,
                    new LdapUser(username, username, null)));
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

    private string BuildBindIdentity(string loginInput, string username)
    {
        if (loginInput.Contains('@', StringComparison.Ordinal))
        {
            return loginInput;
        }

        if (!string.IsNullOrWhiteSpace(_options.UpnSuffix))
        {
            return $"{username}@{_options.UpnSuffix}";
        }

        if (!string.IsNullOrWhiteSpace(_options.Domain))
        {
            return $"{_options.Domain}\\{username}";
        }

        return username;
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

    private static AuthType ResolveAuthType(string authType) =>
        authType.Equals("basic", StringComparison.OrdinalIgnoreCase)
            ? AuthType.Basic
            : AuthType.Negotiate;

    private static string EscapeFilterValue(string value) =>
        value
            .Replace(@"\", @"\5c", StringComparison.Ordinal)
            .Replace("*", @"\2a", StringComparison.Ordinal)
            .Replace("(", @"\28", StringComparison.Ordinal)
            .Replace(")", @"\29", StringComparison.Ordinal)
            .Replace("\u0000", @"\00", StringComparison.Ordinal);
}
