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
    public sealed record LocalNetwork(string Address, int Prefix, IReadOnlyList<string> Gateways);
    public static IReadOnlyList<string> Candidates() => Candidates(NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .SelectMany(n => {
            var properties = n.GetIPProperties();
            var gateways = properties.GatewayAddresses.Select(g => g.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToArray();
            return properties.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => new LocalNetwork(a.Address.ToString(), a.PrefixLength, gateways));
        }));
    // Probe gateways first, then two conventional edge hosts per directly attached subnet.
    // Never enumerate a subnet or use a fixed router address.
    public static IReadOnlyList<string> Candidates(IEnumerable<LocalNetwork> networks)
    {
        var local = networks.ToArray();
        var own = local.Select(n => n.Address).ToHashSet();
        var candidates = local.SelectMany(n => n.Gateways).ToList();
        foreach (var n in local.Where(n => n.Prefix is >= 8 and <= 30))
        {
            if (!IPAddress.TryParse(n.Address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) continue;
            var bytes = ip.GetAddressBytes();
            uint value = (uint)bytes[0]<<24 | (uint)bytes[1]<<16 | (uint)bytes[2]<<8 | bytes[3];
            uint mask = uint.MaxValue << (32-n.Prefix), network = value & mask;
            foreach (uint host in new[] { network+1, network|(~mask-1) })
                candidates.Add(new IPAddress(new byte[]{(byte)(host>>24),(byte)(host>>16),(byte)(host>>8),(byte)host}).ToString());
        }
        return candidates.Where(a => IPAddress.TryParse(a,out var ip) && ip.AddressFamily==AddressFamily.InterNetwork &&
            !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any) && !own.Contains(a)).Distinct().Take(16).ToArray();
    }
    public static async Task<bool> HasSshAsync(string address, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(2));
        using var tcp = new TcpClient();
        try { await tcp.ConnectAsync(address, 22, timeout.Token); return true; }
        catch (Exception e) when (e is SocketException or OperationCanceledException) { ct.ThrowIfCancellationRequested(); return false; }
    }
}
public sealed class SshRouterSession(Func<string, string, bool> trustHost) : IRouterSession, IRouterTransport, IUploadChannel
{
    private DeploymentUpload? upload;
    private InstallationPlan? reviewedPlan;
    private SshClient? ssh;
    private RouterIdentity? identity;
    private readonly Dictionary<string, string> trusted = [];
    public bool IsDemo => false;
    public Task<IAsyncDisposable> AcquireInstallerLockAsync(CancellationToken ct) =>
        ssh?.IsConnected == true ? SshInstallerLock.AcquireAsync(ssh, ct) : throw new SafeFailure("Reconnect before installing.");
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
        using var cmd = ssh.CreateCommand(command);
        cmd.CommandTimeout = TimeSpan.FromSeconds(command == "/root/hotswapper/install-gl-guard.sh --install" ? 90 : 12);
        await cmd.ExecuteAsync(ct);
        if (cmd.ExitStatus != 0) throw new RouterCommandFailure(cmd.ExitStatus);
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
        reviewedPlan = null;
        await ProbeUploadAsync(ct);
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
            ConfigurationGenerator.Housekeeping(c) != ConfigurationGenerator.Housekeeping(reviewedPlan.Configuration) ||
            !c.Guards.Select(d => d.Mac.ToLowerInvariant()).Order().SequenceEqual(reviewedPlan.Configuration.Guards.Select(d => d.Mac.ToLowerInvariant()).Order()))
            throw new SafeFailure("The wizard choices changed. Review the updated plan before installing.");
        await ProbeUploadAsync(ct);
        return await new RouterInstaller(this, new KillSwitchVerifier()).InstallAsync(reviewedPlan, progress, ct);
    }
    public async Task UploadAsync(string path, string content, CancellationToken ct)
    {
        RequireBrume();
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        try { await (upload ??= new DeploymentUpload(this)).UploadAsync(path, bytes, ct); }
        finally { Array.Clear(bytes); }
    }
    public Task<UploadKind> ProbeUploadAsync(CancellationToken ct)
    { RequireBrume(); return (upload ??= new DeploymentUpload(this)).ProbeAsync(ct); }
    Task<string> IUploadChannel.CommandAsync(string command, CancellationToken ct) => ExecuteAsync(command, ct);
    async Task<string> IUploadChannel.StreamAsync(string command, ReadOnlyMemory<byte> bytes, CancellationToken ct)
    {
        if (ssh?.IsConnected != true) throw new SafeFailure("SSH transport disconnected.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var cmd = ssh.CreateCommand(command); cmd.CommandTimeout = TimeSpan.FromSeconds(30);
        var execution = cmd.ExecuteAsync(timeout.Token);
        try {
            using (var input = cmd.CreateInputStream())
                for (int i = 0; i < bytes.Length; i += 8192)
                {
                    timeout.Token.ThrowIfCancellationRequested();
                    await input.WriteAsync(bytes.Slice(i, Math.Min(8192, bytes.Length - i)), timeout.Token);
                }
            await execution;
            if (cmd.ExitStatus != 0) throw new RouterCommandFailure(cmd.ExitStatus);
            if (cmd.Result.Length > 256) throw new SafeFailure("Unexpected SSH stream response.");
            return cmd.Result;
        } catch {
            timeout.Cancel();
            try { await execution; } catch { }
            throw;
        }
    }
    private SftpClient NewSftp()
    {
        if (ssh?.IsConnected != true || identity == null) throw new SafeFailure("SSH transport disconnected.");
        var client = new SftpClient(ssh.ConnectionInfo) { OperationTimeout = TimeSpan.FromSeconds(15) };
        client.HostKeyReceived += (_, e) => {
            var key = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust = trusted.TryGetValue(identity.Address, out var accepted) && key == accepted;
        };
        return client;
    }
    async Task<bool> IUploadChannel.SftpAvailableAsync(CancellationToken ct)
    {
        using var client = NewSftp(); await client.ConnectAsync(ct); return client.IsConnected;
    }
    async Task IUploadChannel.SftpAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken ct)
    {
        using var client = NewSftp(); await client.ConnectAsync(ct);
        byte[] copy = bytes.ToArray();
        try { using var stream = new MemoryStream(copy); await client.UploadFileAsync(stream, path, ct); }
        finally { Array.Clear(copy); }
    }
    private void RequireBrume() { if (identity?.IsBrume != true) throw new SafeFailure("Device verification must identify a GL-MT5000 before continuing."); }
    public void Dispose() { ssh?.Dispose(); ssh = null; identity = null; reviewedPlan = null; upload = null; }
}
public static class NtfyService
{
    public static async Task TestAsync(string url, bool demo, CancellationToken ct)
    {
        var uri = new Uri(NtfyTopic.Normalize(url));
        if (demo) { await Task.Delay(250, ct); return; }
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new StringContent("Brume 3 Hotswapper installer test notification") };
        using var response = await client.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) throw new SafeFailure("The notification service did not accept the test. Check your private URL.");
    }
}
