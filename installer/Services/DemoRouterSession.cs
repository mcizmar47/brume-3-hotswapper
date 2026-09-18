using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
// Explicit --demo fixture only. Never opens a network connection or delegates to real services.
public sealed class DemoRouterSession : IRouterSession
{
    public bool IsDemo => true;
    public async Task<RouterIdentity> ConnectAsync(string address, string password, CancellationToken ct)
    { await Task.Delay(300, ct); return new("192.0.2.1", "GL.iNet GL-MT5000", "glinet,gl-mt5000", "4.9.0", CompatibilityCatalog.StockHash); }
    public Task<IReadOnlyList<VpnProfile>> ProfilesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); var peers = new List<VpnConnection>(); int id = 1;
        foreach (var (location, count) in new[] { ("Croatia,Zagreb", 3), ("Austria,Vienna", 2), ("Spain,Barcelona", 2), ("Norway,Oslo", 1), ("Malta,Valletta", 1), ("United States,New York", 2), ("United States,Boston", 1) })
            for (int i = 0; i < count; i++) peers.Add(new((id++).ToString(), $"Demo connection {id}", location));
        return Task.FromResult<IReadOnlyList<VpnProfile>>([new("42", "7", peers)]);
    }
    public Task<IReadOnlyList<LanClient>> ClientsAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<LanClient>>([new("DESKTOP", "192.0.2.20", "02:00:00:00:00:20"), new("LAPTOP", "192.0.2.21", "02:00:00:00:00:21", true),
            new("Pixel phone", "192.0.2.22", "02:00:00:00:00:22"), new("TV", "192.0.2.23", "02:00:00:00:00:23")]);
    }
    public async Task<InstallationPlan> PlanAsync(InstallerConfiguration c, CancellationToken ct)
    {
        var clients = await ClientsAsync(ct);
        var lan = new LanInventory(new("192.0.2.1", "255.255.255.0", 10, 200), clients,
            clients.Where(d => d.Reserved).Select(d => new Reservation("demo", d.Mac, d.Ip)).ToArray());
        return DeploymentPlanning.Create(c, new(c.Router, "demo", "wgclient1", c.Profile.Connections[0].PeerId, "", lan,
            DeploymentPlanning.Paths.Select(p => new FileState(p, "", "", false)).ToArray(), false));
    }
    public async Task<InstallationResult> InstallAsync(InstallerConfiguration c, IProgress<string> progress, CancellationToken ct)
    {
        foreach (var step in InstallationPlanner.Create(c)) { progress.Report("DEMO · " + step.Name); await Task.Delay(350, ct); }
        return new(true, ["DEMO · script permissions valid", "DEMO · GL guard installed", "DEMO · one watchdog daemon running",
            "DEMO · CURRENT / DOWNTIER / UPTIER topology healthy", "DEMO · kill switch enabled", "DEMO · configuration and cron valid", "No real router operations were performed."]);
    }
    public void Dispose() { }
}
