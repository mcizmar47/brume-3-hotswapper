using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using Renci.SshNet;

namespace BrumeHotswapper.Installer.Services;

public interface IRouterSession : IDisposable
{
    bool IsDemo { get; }
    Task<RouterIdentity> ConnectAsync(string address, string password, CancellationToken ct);
    Task<IReadOnlyList<VpnProfile>> ProfilesAsync(CancellationToken ct);
    Task<IReadOnlyList<LanClient>> ClientsAsync(CancellationToken ct);
    Task<InstallationPlan> PlanAsync(InstallerConfiguration configuration, CancellationToken ct);
    Task<InstallationResult> InstallAsync(InstallerConfiguration configuration, IProgress<string> progress, CancellationToken ct);
}
public static class RouterDiscovery
{
    // Bounded to directly attached default gateways: no subnet-wide password spraying.
    public static IReadOnlyList<string> Candidates() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(n => n.GetIPProperties().GatewayAddresses)
        .Select(g => g.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))
        .Select(a => a.ToString()).Distinct().Take(8).ToArray();
    public static async Task<bool> HasSshAsync(string address, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(1));
        using var tcp = new TcpClient();
        try { await tcp.ConnectAsync(address, 22, timeout.Token); return true; }
        catch (Exception e) when (e is SocketException or OperationCanceledException) { ct.ThrowIfCancellationRequested(); return false; }
    }
}
public sealed class SshRouterSession(Func<string, string, bool> trustHost) : IRouterSession, IRouterTransport
{
    private InstallationPlan? reviewedPlan;
    private SshClient? ssh;
    private RouterIdentity? identity;
    private readonly Dictionary<string, string> trusted = [];
    public bool IsDemo => false;
    public async Task<RouterIdentity> ConnectAsync(string address, string password, CancellationToken ct)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new SafeFailure("Enter an IPv4 router address.");
        Dispose();
        var connection = new PasswordConnectionInfo(address, "root", password) { Timeout = TimeSpan.FromSeconds(6) };
        ssh = new SshClient(connection);
        ssh.HostKeyReceived += (_, e) =>
        {
            string fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust = trusted.TryGetValue(address, out var previous) ? previous == fingerprint : trustHost(address, fingerprint);
            if (e.CanTrust) trusted[address] = fingerprint;
        };
        try
        {
            await ssh.ConnectAsync(ct);
            // Verified live GL-MT5000 identity and firmware sources.
            var board = JsonDocument.Parse(await ExecuteAsync("ubus call system board", ct));
            using (board)
            {
                string Field(string name) => board.RootElement.TryGetProperty(name, out var v) ? v.GetString() ?? "Unknown" : "Unknown";
                identity = new(address, Field("model"), Field("board_name"), "Not checked", "");
                if (!identity.IsBrume) return identity;
                var firmware = (await ExecuteAsync("if [ -r /etc/glversion ]; then head -n 1 /etc/glversion; else printf 'Unknown'; fi", ct)).Trim();
                // Do not classify arbitrary /etc/glversion contents as tested firmware.
                if (!Regex.IsMatch(firmware, "^[0-9]+\\.[0-9]+\\.[0-9]+$")) firmware = "Unknown";
                var hash = (await ExecuteAsync("sha256sum /usr/bin/rtp2.sh | awk '{print $1}'", ct)).Trim();
                identity = new(address, Field("model"), Field("board_name"), firmware, hash);
                return identity;
            }
        }
        catch (OperationCanceledException) { Dispose(); throw; }
        catch { Dispose(); throw new SafeFailure("SSH authentication or device interrogation failed. Check the address, SSH access and administrator password."); }
    }
    public async Task<string> ExecuteAsync(string command, CancellationToken ct)
    {
        if (ssh?.IsConnected != true) throw new SafeFailure("The SSH session is disconnected. Reconnect to the router.");
        using var cmd = ssh.CreateCommand(command); cmd.CommandTimeout = TimeSpan.FromSeconds(12);
        await cmd.ExecuteAsync(ct);
        if (cmd.ExitStatus != 0) throw new SafeFailure("A required router command failed. No raw router output was added to the report.");
        if (cmd.Result.Length > 512_000) throw new SafeFailure("Router response exceeded the expected size.");
        return cmd.Result;
    }
    public Task<IReadOnlyList<VpnProfile>> ProfilesAsync(CancellationToken ct)
    { RequireBrume(); return new VpnDiscovery(this).DiscoverAsync(ct); }
    public async Task<IReadOnlyList<LanClient>> ClientsAsync(CancellationToken ct)
    {
        RequireBrume();
        return (await new RouterInspection(this, new KillSwitchVerifier()).LanAsync(ct)).Clients;
    }
    public async Task<InstallationPlan> PlanAsync(InstallerConfiguration c, CancellationToken ct)
    {
        RequireBrume();
        reviewedPlan = await new RouterInstaller(this, new KillSwitchVerifier()).PlanAsync(c, ct);
        return reviewedPlan;
    }
    public async Task<InstallationResult> InstallAsync(InstallerConfiguration c, IProgress<string> progress, CancellationToken ct)
    {
        RequireBrume();
        if (reviewedPlan == null) throw new SafeFailure("Review an installation plan before installing.");
        if (ConfigurationGenerator.PrivateConfig(c) != ConfigurationGenerator.PrivateConfig(reviewedPlan.Configuration) ||
            ConfigurationGenerator.Locations(c) != ConfigurationGenerator.Locations(reviewedPlan.Configuration) ||
            c.Maintenance != reviewedPlan.Configuration.Maintenance ||
            !c.Guards.Select(d => d.Mac.ToLowerInvariant()).Order().SequenceEqual(reviewedPlan.Configuration.Guards.Select(d => d.Mac.ToLowerInvariant()).Order()))
            throw new SafeFailure("The wizard choices changed. Review the updated plan before installing.");
        return await new RouterInstaller(this, new KillSwitchVerifier()).InstallAsync(reviewedPlan, progress, ct);
    }
    public async Task UploadAsync(string path, string content, CancellationToken ct)
    {
        if (ssh?.IsConnected != true || identity == null) throw new SafeFailure("Reconnect to the router before uploading.");
        if (!path.StartsWith("/root/.hotswap-installer/transaction/", StringComparison.Ordinal))
            throw new SafeFailure("Upload path is outside protected staging.");
        using var sftp = new SftpClient(ssh.ConnectionInfo);
        sftp.HostKeyReceived += (_, e) =>
        {
            var key = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust = trusted.TryGetValue(identity.Address, out var accepted) && key == accepted;
        };
        await sftp.ConnectAsync(ct);
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
        await sftp.UploadFileAsync(stream, path, ct);
        await Task.Run(() => sftp.ChangePermissions(path, 384), ct); // 0600
    }
    // Fixed-path raw SSH read. Do not access Result: decoding text could alter firmware bytes.
    public async Task<byte[]> ReadFirmwareBytesAsync(CancellationToken ct)
    {
        RequireBrume();
        if (ssh?.IsConnected != true) throw new SafeFailure("Reconnect before reading firmware.");
        using var command = ssh.CreateCommand("cat /usr/bin/rtp2.sh");
        command.CommandTimeout = TimeSpan.FromSeconds(12);
        await command.ExecuteAsync(ct);
        if (command.ExitStatus != 0) throw new SafeFailure("Read-only firmware cat failed; stderr withheld.");
        return await FirmwareRead.CopyBoundedAsync(command.OutputStream, ct);
    }
    // Diagnose the old path separately. No upload, remote temporary file or raw exception reporting.
    public async Task<string> ProbeFirmwareSftpAsync(CancellationToken ct)
    {
        RequireBrume();
        if (ssh?.IsConnected != true || identity == null) throw new SafeFailure("Reconnect before the SFTP probe.");
        string stage = "connect/subsystem initialization";
        using var sftp = new SftpClient(ssh.ConnectionInfo);
        sftp.HostKeyReceived += (_, e) =>
        {
            var key = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust = trusted.TryGetValue(identity.Address, out var accepted) && key == accepted;
        };
        try
        {
            await sftp.ConnectAsync(ct);
            stage = "file attributes";
            var attributes = sftp.GetAttributes("/usr/bin/rtp2.sh");
            if (attributes.Size > FirmwareRead.MaximumBytes) return "File exceeds probe limit.";
            stage = "file read";
            using var stream = sftp.OpenRead("/usr/bin/rtp2.sh");
            var bytes = await FirmwareRead.CopyBoundedAsync(stream, ct);
            Array.Clear(bytes);
            return "SFTP connect, attributes and read succeeded; no upload attempted.";
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { return "SFTP failed during " + stage + ": " + FirmwareRead.FailureCategory(e); }
    }
    private void RequireBrume() { if (identity?.IsBrume != true) throw new SafeFailure("Device verification must identify a GL-MT5000 before continuing."); }
    public void Dispose() { ssh?.Dispose(); ssh = null; identity = null; reviewedPlan = null; }
}
public static class NtfyService
{
    public static async Task TestAsync(string url, bool demo, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo) || url.Any(char.IsControl))
            throw new SafeFailure("Enter a valid HTTPS ntfy topic URL.");
        if (demo) { await Task.Delay(250, ct); return; }
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new StringContent("Brume 3 Hotswapper installer test notification") };
        using var response = await client.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) throw new SafeFailure("The notification service did not accept the test. Check your private URL.");
    }
}
