namespace WebSiteKontrol.Auth;

public sealed class LoginSecurityOptions
{
    public const string SectionName = "LoginSecurity";

    public bool UseEmailLoginOnly { get; set; } = true;
    public string AllowedEmailDomain { get; set; } = "kastamonu.edu.tr";
    public List<string> AllowedLoginEmails { get; set; } = new();
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 15;
    public int AttemptWindowMinutes { get; set; } = 15;
    public int LogRetentionMinutes { get; set; } = 1440;
}
