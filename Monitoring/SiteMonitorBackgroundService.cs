using System.Collections.Concurrent;
using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace WebSiteKontrol.Monitoring;

public sealed class SiteMonitorBackgroundService : BackgroundService
{
    private const string UbysHost = "ubys.kastamonu.edu.tr";
    private const string UbysSupportEmail = "ubysdestek@kastamonu.edu.tr";

    private static readonly Regex UrlRegex = new(
        @"https?://[a-zA-Z0-9\.-]+(?:/[^\s""'<>]*)?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly ILogger<SiteMonitorBackgroundService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IWebHostEnvironment _environment;
    private readonly IOptionsMonitor<SiteMonitorOptions> _monitorOptions;
    private readonly IOptionsMonitor<SmtpOptions> _smtpOptions;
    private readonly ManagedSiteRegistry _managedSiteRegistry;
    private readonly ConcurrentDictionary<string, bool> _latestStates = new(StringComparer.OrdinalIgnoreCase);
    private List<string> _urls = new();

    public SiteMonitorBackgroundService(
        ILogger<SiteMonitorBackgroundService> logger,
        IHttpClientFactory httpClientFactory,
        IWebHostEnvironment environment,
        IOptionsMonitor<SiteMonitorOptions> monitorOptions,
        IOptionsMonitor<SmtpOptions> smtpOptions,
        ManagedSiteRegistry managedSiteRegistry)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _environment = environment;
        _monitorOptions = monitorOptions;
        _smtpOptions = smtpOptions;
        _managedSiteRegistry = managedSiteRegistry;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var options = _monitorOptions.CurrentValue;
        if (!options.Enabled)
        {
            _logger.LogInformation("Background monitor devre disi (Monitoring:Enabled=false).");
            return;
        }

        _urls = LoadUrlsFromSource(options.SourceFile);
        if (_urls.Count == 0 && _managedSiteRegistry.GetUrls().Count == 0)
        {
            _logger.LogWarning("Izleme URL listesi bos. SourceFile: {SourceFile}", options.SourceFile);
            return;
        }

        _logger.LogInformation("Background monitor basladi.");
        await RunScanCycle(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            var delaySeconds = Math.Max(30, _monitorOptions.CurrentValue.IntervalSeconds);
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), stoppingToken);
            await RunScanCycle(stoppingToken);
        }
    }

    private async Task RunScanCycle(CancellationToken cancellationToken)
    {
        var options = _monitorOptions.CurrentValue;
        var parallelism = Math.Max(1, options.MaxParallelChecks);
        var downCount = 0;

        var scanUrls = _urls
            .Concat(_managedSiteRegistry.GetUrls())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        await Parallel.ForEachAsync(
            scanUrls,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = parallelism,
                CancellationToken = cancellationToken,
            },
            async (url, token) =>
            {
                var isUp = await CheckSiteAsync(url, token);
                var hasPrevious = _latestStates.TryGetValue(url, out var wasUp);
                _latestStates[url] = isUp;

                if (!isUp)
                {
                    Interlocked.Increment(ref downCount);
                }

                if (!hasPrevious)
                {
                    return;
                }

                if (wasUp && !isUp)
                {
                    await SendAlertEmailAsync(url, isRecovery: false, token);
                }
                else if (!wasUp && isUp && _monitorOptions.CurrentValue.AlertOnRecovery)
                {
                    await SendAlertEmailAsync(url, isRecovery: true, token);
                }
            });

        _logger.LogInformation(
            "Izleme dongusu tamamlandi. Toplam: {Total}, Pasif: {Down}, Zaman: {Time}",
            scanUrls.Count,
            downCount,
            DateTime.Now);
    }

    private async Task<bool> CheckSiteAsync(string url, CancellationToken cancellationToken)
    {
        var options = _monitorOptions.CurrentValue;
        using var client = _httpClientFactory.CreateClient("SiteMonitor");
        client.Timeout = TimeSpan.FromSeconds(Math.Max(3, options.RequestTimeoutSeconds));

        try
        {
            using var headRequest = new HttpRequestMessage(HttpMethod.Head, url);
            using var headResponse = await client.SendAsync(headRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (headResponse.IsSuccessStatusCode)
            {
                return true;
            }
        }
        catch
        {
            // HEAD her sunucuda desteklenmeyebilir; GET fallback uygulanir.
        }

        try
        {
            using var getRequest = new HttpRequestMessage(HttpMethod.Get, url);
            using var getResponse = await client.SendAsync(getRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return (int)getResponse.StatusCode < 500;
        }
        catch
        {
            return false;
        }
    }

    private async Task SendAlertEmailAsync(string url, bool isRecovery, CancellationToken cancellationToken)
    {
        var smtp = _smtpOptions.CurrentValue;
        if (!smtp.Enabled || string.IsNullOrWhiteSpace(smtp.Host) || string.IsNullOrWhiteSpace(smtp.From) || smtp.To.Count == 0)
        {
            _logger.LogWarning("SMTP ayarlari eksik/devre disi. Alarm maili atlanacak: {Url}", url);
            return;
        }

        var subject = isRecovery
            ? $"[Web Durum Takibi] Site tekrar aktif: {url}"
            : $"[Web Durum Takibi] Site pasif: {url}";

        var body =
            $"Durum: {(isRecovery ? "AKTIF" : "PASIF")}\n" +
            $"Site: {url}\n" +
            $"Zaman: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
            $"Kaynak: websitekontrol.kastamonu.edu.tr";

        using var message = new MailMessage
        {
            From = new MailAddress(smtp.From),
            Subject = subject,
            Body = body,
        };

        foreach (var recipient in smtp.To.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            message.To.Add(recipient.Trim());
        }

        if (!isRecovery &&
            Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            string.Equals(uri.Host, UbysHost, StringComparison.OrdinalIgnoreCase) &&
            !message.To.Cast<MailAddress>().Any(x => string.Equals(x.Address, UbysSupportEmail, StringComparison.OrdinalIgnoreCase)))
        {
            message.To.Add(UbysSupportEmail);
        }

        if (message.To.Count == 0)
        {
            return;
        }

        using var mailClient = new SmtpClient(smtp.Host, smtp.Port)
        {
            EnableSsl = smtp.UseSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
        };

        if (!string.IsNullOrWhiteSpace(smtp.Username))
        {
            mailClient.Credentials = new NetworkCredential(smtp.Username, smtp.Password);
        }

        try
        {
            await mailClient.SendMailAsync(message, cancellationToken);
            _logger.LogInformation("Alarm maili gonderildi. Site: {Url}, Recovery: {Recovery}", url, isRecovery);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Alarm maili gonderilemedi. Site: {Url}", url);
        }
    }

    private List<string> LoadUrlsFromSource(string sourceFile)
    {
        var fullPath = Path.Combine(_environment.ContentRootPath, sourceFile);
        if (!File.Exists(fullPath))
        {
            return new List<string>();
        }

        var content = File.ReadAllText(fullPath);
        var urls = UrlRegex
            .Matches(content)
            .Select(m => m.Value.Trim().TrimEnd('"', '\'', ',', ';'))
            .Where(u => Uri.TryCreate(u, UriKind.Absolute, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return urls;
    }
}
