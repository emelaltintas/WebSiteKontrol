namespace WebSiteKontrol.Monitoring;

public sealed class SiteMonitorOptions
{
    public const string SectionName = "Monitoring";

    public bool Enabled { get; set; } = true;
    public int IntervalSeconds { get; set; } = 300;
    public int RequestTimeoutSeconds { get; set; } = 12;
    public int MaxParallelChecks { get; set; } = 20;
    public string SourceFile { get; set; } = "index.html";
    public bool AlertOnRecovery { get; set; } = false;
}
