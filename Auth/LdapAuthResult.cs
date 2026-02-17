namespace WebSiteKontrol.Auth;

public sealed record LdapAuthResult(bool Success, LdapUser? User);
