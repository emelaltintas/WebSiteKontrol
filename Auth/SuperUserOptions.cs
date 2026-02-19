namespace WebSiteKontrol.Auth;

public sealed class SuperUserOptions
{
    public const string SectionName = "SuperUsers";

    public List<string> Emails { get; set; } = new();
}
