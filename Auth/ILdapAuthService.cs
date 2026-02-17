namespace WebSiteKontrol.Auth;

public interface ILdapAuthService
{
    Task<LdapAuthResult> AuthenticateAsync(string usernameOrEmail, string password, CancellationToken cancellationToken = default);
}
