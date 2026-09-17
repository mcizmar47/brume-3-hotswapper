using System.Collections.ObjectModel;
using System.Windows.Input;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;

namespace BrumeHotswapper.Installer.ViewModels;

public sealed class RelayCommand(Action execute, Func<bool>? can = null) : ICommand
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => can?.Invoke() ?? true;
    public void Execute(object? parameter) => execute();
    public void Refresh() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
public sealed class WizardViewModel : Observable, IDisposable
{
    private readonly Func<string, string, bool> trust;
    private IRouterSession? session;
    private CancellationTokenSource? operation;
    private readonly DiagnosticLog log = new();
    private int page;
    private bool busy, demo, acknowledged, unknownAccepted, locationAccepted, notifications, maintenance;
    private string status = "Ready", manualAddress = "", review = "", ntfyUrl = "";
    private RouterIdentity? router;
    private VpnProfile? selectedProfile;
    private bool installed;
    private InstallationPlan? plan;
    public static readonly string[] PageTitles = ["Welcome", "Find your Brume", "Verify device", "Compatibility", "Discover VPNs", "Arrange failover", "Notifications", "Maintenance", "Review", "Installation", "Validation", "Complete"];
    public WizardViewModel(Func<string, string, bool> trust)
    {
        this.trust = trust;
        NextCommand = new(() => _ = RunAsync(NextAsync), CanNext);
        BackCommand = new(() => { Page--; }, () => !Busy && Page > 0 && Page < 9);
        CancelCommand = new(() => operation?.Cancel(), () => Busy);
        TestNotificationCommand = new(() => _ = RunAsync(async ct => { await NtfyService.TestAsync(NtfyUrl, Demo, ct); Status = Demo ? "DEMO · notification simulated" : "Test delivered from this PC. Router delivery still needs validation."; }), () => !Busy && Notifications);
        Demo = Environment.GetCommandLineArgs().Contains("--demo");
    }
    public RelayCommand NextCommand { get; }
    public RelayCommand BackCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand TestNotificationCommand { get; }
    public int Page { get => page; private set { Set(ref page, value); Changed(nameof(Title)); Changed(nameof(StepLabel)); Changed(nameof(NextLabel)); Refresh(); } }
    public string Title => PageTitles[Page];
    public string StepLabel => $"STEP {Page + 1} OF {PageTitles.Length}";
    public string NextLabel => Page == 8 ? (Demo ? "Simulate install" : "Install") : Page == 10 ? "Finish" : "Next →";
    public bool Busy { get => busy; private set { Set(ref busy, value); Changed(nameof(Idle)); Refresh(); } }
    public bool Idle => !Busy;
    public bool Demo { get => demo; set { if (Set(ref demo, value)) { session?.Dispose(); session = null; ResetConnection(); Changed(nameof(ModeLabel)); } } }
    public string ModeLabel => Demo ? "DEMO · no network or router changes" : "";
    public bool Acknowledged { get => acknowledged; set { Set(ref acknowledged, value); Refresh(); } }
    public bool UnknownAccepted { get => unknownAccepted; set { Set(ref unknownAccepted, value); Refresh(); } }
    public bool LocationAccepted { get => locationAccepted; set { Set(ref locationAccepted, value); Refresh(); } }
    public bool Notifications { get => notifications; set { Set(ref notifications, value); Refresh(); } }
    public bool Maintenance { get => maintenance; set => Set(ref maintenance, value); }
    public string NtfyUrl { get => ntfyUrl; set => Set(ref ntfyUrl, value); }
    public string ManualAddress { get => manualAddress; set => Set(ref manualAddress, value); }
    public string Status { get => status; private set => Set(ref status, value); }
    public string Review { get => review; private set => Set(ref review, value); }
    public RouterIdentity? Router { get => router; private set { Set(ref router, value); Changed(nameof(DeviceSummary)); Changed(nameof(CompatibilitySummary)); Changed(nameof(CompatibilityDetails)); Refresh(); } }
    public string DeviceSummary => Router is null ? "No router connected." : $"{Router.Model}\nAddress: {Router.Address}\n\n" + (Router.IsBrume ? "GL-MT5000 verified. You may continue." : "Unsupported device. Installation is blocked; connect to a Brume 3 / GL-MT5000.");
    public string CompatibilityDetails => Router == null ? "" : $"Board: {Router.Board}\nAddress: {Router.Address}\nrtp2 SHA-256: {Router.Rtp2Hash}";
    public string CompatibilitySummary => Router is null ? "" : $"Firmware: {Router.Firmware}\n"
        + (CompatibilityCatalog.TestedFirmware.Contains(Router.Firmware) ? "Tested firmware version." : "This firmware version has not been tested. Installation is blocked.")
        + "\n\n" + (CompatibilityCatalog.Classify(Router.Rtp2Hash) switch
        {
            Compatibility.StockKnownCompatible => "Known compatible GL VPN implementation.",
            Compatibility.AlreadyPatchedKnownCompatible => "Existing GL reconciliation guard detected.",
            Compatibility.KnownIncompatible => "This GL VPN implementation is known to be incompatible. Installation cannot continue.",
            _ => "The GL VPN reconciliation implementation is unknown. Installation is blocked until its compatibility is established."
        });
    public VpnProfile? SelectedProfile { get => selectedProfile; set { if (Set(ref selectedProfile, value)) { foreach (var t in Tiers) t.Locations.Clear(); if (value != null) foreach (var g in new ExactLocationResolver().Group(value.Connections)) Tiers[0].Locations.Add(g); LocationAccepted = false; Refresh(); } } }
    public ObservableCollection<VpnProfile> Profiles { get; } = [];
    public ObservableCollection<TierColumn> Tiers { get; } = [new("Unassigned", 0), new("Tier 1 · preferred", 1), new("Tier 2 · fallback", 2), new("Tier 3 · last resort", 3)];
    public ObservableCollection<LanClient> Clients { get; } = [];
    public ObservableCollection<string> Progress { get; } = [];
    public ObservableCollection<string> Validation { get; } = [];
    public string Report => log.Report(Demo);
    public async Task ConnectAsync(string password, bool manual)
    {
        await RunAsync(async ct =>
        {
            ResetConnection();
            session ??= Demo ? new DemoRouterSession() : new SshRouterSession(trust);
            if (!Demo && string.IsNullOrEmpty(password)) throw new SafeFailure("Enter the router administrator password.");
            var candidates = Demo ? new[] { "192.0.2.1" } : manual ? new[] { ManualAddress.Trim() } : RouterDiscovery.Candidates();
            int authenticationAttempts = 0;
            foreach (var address in candidates)
            {
                ct.ThrowIfCancellationRequested(); Status = $"Checking {address}…";
                if (!Demo && !await RouterDiscovery.HasSshAsync(address, ct)) continue;
                if (++authenticationAttempts > 4) break;
                try
                {
                    Router = await session.ConnectAsync(address, password, ct);
                    if (Router.IsBrume || manual || Demo) { Page = 2; Status = Router.IsBrume ? "Router identity verified." : "Unsupported device — installation blocked."; return; }
                }
                catch (SafeFailure) { if (manual) throw; }
            }
            if (Router != null) { Page = 2; Status = "No supported Brume found."; }
            else throw new SafeFailure("No Brume found among local gateways and subnet edge addresses. Use the manual IPv4 address fallback; check SSH access and password.");
        });
    }
    private void ResetConnection()
    { Router = null; Profiles.Clear(); SelectedProfile = null; Clients.Clear(); UnknownAccepted = false; installed = false; }
    private bool CanNext() => !Busy && Page switch
    {
        0 => Acknowledged, 1 => false, 2 => Router?.IsBrume == true,
        3 => Router != null && CompatibilityCatalog.Classify(Router.Rtp2Hash) != Compatibility.KnownIncompatible
            && CompatibilityCatalog.Classify(Router.Rtp2Hash) != Compatibility.Unknown && CompatibilityCatalog.TestedFirmware.Contains(Router.Firmware),
        4 => SelectedProfile != null,
        9 => false, 10 => installed, 11 => false, _ => true
    };
    private InstallerConfiguration Configuration() => new(Router ?? throw new SafeFailure("Connect to a router first."),
        SelectedProfile ?? throw new SafeFailure("Select a discovered VPN profile."), Tiers.ToArray(), Notifications, NtfyUrl, Maintenance,
        Maintenance ? Clients.Where(c => c.Selected).ToArray() : []);
    private async Task NextAsync(CancellationToken ct)
    {
        switch (Page)
        {
            case 3:
                Profiles.Clear(); Status = "Reading existing VPN profile metadata…";
                foreach (var p in await session!.ProfilesAsync(ct)) Profiles.Add(p);
                SelectedProfile = VpnDiscovery.AutoSelect(Profiles.ToArray());
                if (Profiles.Count == 0) Status = "No supported VPN lists found. Import VPN List connections and enable the selected VPN in the GL panel.";
                else if (Profiles.Count > 1) Status = "Select the VPN list you want Hotswapper to manage.";
                break;
            case 5: ConfigurationGenerator.Validate(Configuration() with { Notifications = false }); break;
            case 6:
                ConfigurationGenerator.Validate(Configuration()); Clients.Clear(); Status = "Reading LAN clients…";
                try { foreach (var client in await session!.ClientsAsync(ct)) Clients.Add(client); }
                catch (SafeFailure) { Status = "LAN clients could not be read. Maintenance may remain disabled; check the LAN IPv4/DHCP configuration before selecting protected devices."; }
                break;
            case 7:
                var c = Configuration(); ConfigurationGenerator.Validate(c);
                plan = await session!.PlanAsync(c, ct);
                Review = BuildReview(c) + $"\n\nGL.iNet kill switch: {(plan.Snapshot.KillSwitchEnabled ? "Enabled" : "Disabled — direct WAN fallback is permitted by the current GL.iNet VPN policy")} (preserved)" + "\n\nPLANNED CHANGES\n" + string.Join("\n", plan.Changes); break;
            case 8:
                var config = Configuration(); ConfigurationGenerator.Validate(config); Progress.Clear(); Page = 9;
                try
                {
                    var progress = new Progress<string>(s => { Progress.Add(s); Status = s; log.Add(s); });
                    var result = await session!.InstallAsync(config, progress, ct);
                    installed = result.Success; Validation.Clear(); foreach (var check in result.Checks) { Validation.Add(check); log.Add(check); }
                    if (installed) { NtfyUrl = ""; plan = null; session?.Dispose(); session = null; }
                    Page = 10; Status = Demo ? "Simulation complete. Review the simulated validation results." : "Validation finished.";
                }
                catch { Page = 8; throw; }
                return;
            case 10:
                NtfyUrl = ""; session?.Dispose(); session = null;
                Status = Demo ? "Demo complete. No real installation was performed." : "Installation complete.";
                break;
        }
        Page++;
    }
    private static string BuildReview(InstallerConfiguration c) => $"ROUTER\n{c.Router.Model} · {c.Router.Address}\nFirmware: {c.Router.Firmware} · {(CompatibilityCatalog.TestedFirmware.Contains(c.Router.Firmware) ? "tested" : "untested")}\nrtp2: {CompatibilityCatalog.Classify(c.Router.Rtp2Hash)}\nVPN list: {c.Profile.Display}\n\nVPN LOCATIONS\n"
        + string.Join("\n\n", c.Tiers.Select(t => t.Title + "\n" + (t.Locations.Count == 0 ? "  None" : string.Join('\n', t.Locations.Select((g, i) => $"  {i + 1}. {g.Label} ({g.Connections.Count} connections)")))))
        + $"\n\nNotifications: {(c.Notifications ? "Enabled (private URL hidden)" : "Disabled")}\nMaintenance reboot: {(c.Maintenance ? "Enabled · 03:00–14:00 hourly, router time" : "Disabled · script still installed")}\nReboot guards: {string.Join(", ", c.Guards.Select(g => g.Hostname))}\n\nCOMPONENTS\nHotswapper · supervisor · housekeeping · GL reconciliation guard\nPrivate configuration · location pools · supervisor cron every 5 minutes\n\nThe selected VPN connection will be checked again before applying these changes. No router reboot or synthetic failover will be performed.";
    public void Move(VpnLocationGroup group, TierColumn target, int index)
    {
        if (Busy) return;
        var source = Tiers.Single(t => t.Locations.Contains(group)); int old = source.Locations.IndexOf(group);
        if (source == target && old < index) index--;
        source.Locations.Remove(group); target.Locations.Insert(Math.Clamp(index, 0, target.Locations.Count), group); Refresh();
    }
    private async Task RunAsync(Func<CancellationToken, Task> action)
    {
        if (Busy) return;
        using var cts = new CancellationTokenSource(); operation = cts; Busy = true;
        try { await action(cts.Token); }
        catch (OperationCanceledException) { Status = "Operation cancelled. No installation completed."; log.Add("Operation cancelled."); }
        catch (SafeFailure e) { Status = e.Message; log.Add(e.Message); }
        catch { Status = "The operation failed. Check connectivity and try again. Sensitive diagnostic details were withheld."; log.Add("Operation failed; raw exception withheld."); }
        finally { Busy = false; operation = null; Changed(nameof(Report)); }
    }
    private void Refresh() { NextCommand?.Refresh(); BackCommand?.Refresh(); CancelCommand?.Refresh(); TestNotificationCommand?.Refresh(); }
    public void Dispose() { operation?.Cancel(); session?.Dispose(); session = null; plan = null; NtfyUrl = ""; }
}
