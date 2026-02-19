namespace WebSiteKontrol.Monitoring;

public sealed class ManagedSiteEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Url { get; set; } = "";
    public string GroupKey { get; set; } = "diger";
    public string SiteName { get; set; } = "";
    public string UnitName { get; set; } = "";
    public string ServerId { get; set; } = "";
    public string Platform { get; set; } = "";
    public string ResponsibleName { get; set; } = "";
    public string ResponsibleEmail { get; set; } = "";
    public string ResponsiblePhone { get; set; } = "";
    public string ResponsibleTitle { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}
