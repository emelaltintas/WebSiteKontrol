namespace WebSiteKontrol.Auth;

public sealed class LdapOptions
{
    public const string SectionName = "Ldap";

    public string Server { get; set; } = "dc1.kastamonu.local";
    public int Port { get; set; } = 636;
    public bool UseSsl { get; set; } = true;
    public string BaseDn { get; set; } = "DC=kastamonu,DC=local";
    public string Domain { get; set; } = "kastamonu";
    public string UpnSuffix { get; set; } = "kastamonu.edu.tr";
    public string AuthType { get; set; } = "Negotiate";
    public int TimeoutSeconds { get; set; } = 8;
}
