using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Text.RegularExpressions;
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

public sealed class GuardIpEntry : Observable
{
    private string address = "";
    public string Address { get => address; set => Set(ref address, value); }
}

public sealed class WizardViewModel : Observable, IDisposable
{
    private enum CompatibilityProblem { None, WrongDevice, MissingVpn, InsufficientLocations, InactiveVpn, UnreadableFirmware, WrongFirmware, UnknownFiles }
    private static readonly string[] PageTitles = ["Prerequisites", "Connect", "Compatibility", "Configure Tiers", "Tier 1 Recovery", "Installation"];
    private readonly Func<IRouterSession> createSession;
    private readonly DiagnosticLog log = new();
    private IRouterSession? session;
    private CancellationTokenSource? operation;
    private RouterIdentity? router;
    private VpnProfile? selectedProfile;
    private CompatibilityProblem problem;
    private readonly List<string> vpnCheckFailures = [];
    private IReadOnlyList<LanClient> knownClients = [];
    private bool connected, busy, acceptUnsupportedFirmware, firmwareFilesKnown;
    private bool installed;
    private int page;
    private string status = "Ready", routerAddress = "192.168.8.1", rebootStartText = "", rebootEndText = "";
    private string errorMessage = "";
    private string installationHeadline = "Installing…";
    private readonly bool demo;

    public WizardViewModel(Func<string, string, bool> trust, bool demoMode = false, Func<IRouterSession>? sessionFactory = null)
    {
        demo = demoMode || Environment.GetCommandLineArgs().Contains("--demo");
        createSession = sessionFactory ?? (() => demo ? new DemoRouterSession() : new SshRouterSession(trust));
        BackCommand = new(Back, () => !Busy && Page is > 0 and < 5);
        PrimaryCommand = new(() => _ = RunAsync(NextAsync), CanContinue);
        AddGuardCommand = new(AddGuard, () => !Busy && Page == 4);
    }

    public RelayCommand BackCommand { get; }
    public RelayCommand PrimaryCommand { get; }
    public RelayCommand AddGuardCommand { get; }
    public string ModeLabel => demo ? "DEMO — no router changes" : "";
    public string SupportedVersions => string.Join(", ", CompatibilityCatalog.TestedFirmware.OrderBy(x => x));
    public int Page { get => page; private set { if (Set(ref page, value)) RefreshPresentation(); } }
    public string Title => PageTitles[Page];
    public string StepLabel => Page == 2 ? "CONNECTION CHECK" : Page == 5 ? "INSTALLATION" : $"SETUP · {Page switch { 0 => 1, 1 => 2, 3 => 3, 4 => 4, _ => 1 }} OF 4";
    public string PrimaryLabel => Page switch { 4 => "Install", 2 => "Continue", _ => "Continue" };
    public bool Busy { get => busy; private set { if (Set(ref busy, value)) { Changed(nameof(Idle)); RefreshPresentation(); } } }
    public bool Idle => !Busy;
    public bool ShowBack => Page is > 0 and < 5;
    public bool ShowCancel => Page < 5;
    public bool ShowPrimary => Page is 0 or 3 or 4 || Page == 1 && Connected || Page == 2 && problem == CompatibilityProblem.WrongFirmware;
    public bool ShowSaveLog => Page == 5;
    public bool ShowConnect => Page == 1;
    public bool Connected => connected;
    public bool IsDisconnected => !Connected;
    public bool CanConnect => Page == 1 && !Busy && !Connected;
    public bool CanToggleConnection => Page == 1 && !Busy;
    public string ConnectionButtonLabel => Connected ? "Disconnect" : "Connect";
    public string RouterAddress { get => routerAddress; set => Set(ref routerAddress, value); }
    public string ConnectionSummary => !Connected ? "Not connected." : $"Connected to {Router?.Model} at {Router?.Address} (firmware {Router?.Firmware}).";
    public string Status { get => status; private set => Set(ref status, value); }
    public string ErrorMessage { get => errorMessage; private set { if (Set(ref errorMessage, value)) Changed(nameof(HasErrorMessage)); } }
    public bool HasErrorMessage => ErrorMessage.Length > 0;
    public string InstallationHeadline { get => installationHeadline; private set => Set(ref installationHeadline, value); }
    public ObservableCollection<string> Progress { get; } = [];
    public string InstallationLog => log.Report(demo);

    public ObservableCollection<VpnProfile> EligibleProfiles { get; } = [];
    public ObservableCollection<TierColumn> Tiers { get; } =
        [new("Unassigned", 0), new("Tier 1 · Preferred", 1), new("Tier 2 · Secondary", 2), new("Tier 3 · Backup", 3)];
    public VpnProfile? SelectedProfile
    {
        get => selectedProfile;
        set
        {
            if (!Set(ref selectedProfile, value)) return;
            foreach (var t in Tiers) t.Locations.Clear();
            if (value != null)
                foreach (var group in new ExactLocationResolver().Group(value.Connections)) Tiers[0].Locations.Add(group);
            RefreshPresentation();
        }
    }

    public bool ShowVpnHelp => Page == 2 && (problem is CompatibilityProblem.MissingVpn or CompatibilityProblem.InsufficientLocations or CompatibilityProblem.InactiveVpn);
    public bool ShowFirmwareHelp => Page == 2 && (problem is CompatibilityProblem.UnreadableFirmware or CompatibilityProblem.WrongFirmware or CompatibilityProblem.UnknownFiles);
    public bool ShowFirmwareOverride => Page == 2 && problem == CompatibilityProblem.WrongFirmware;
    public string CompatibilityHeadline => problem switch
    {
        CompatibilityProblem.WrongDevice => "Cannot verify that this device is a GL.iNet Brume 3 (GL-MT5000).",
        CompatibilityProblem.MissingVpn => "No VPN tunnel profile is set up. Cannot continue.",
        CompatibilityProblem.InsufficientLocations => "None of the VPN tunnels contain two distinct geographic locations.",
        CompatibilityProblem.InactiveVpn => "No VPN tunnel passed the active WireGuard check.",
        CompatibilityProblem.UnreadableFirmware => "The router's firmware version could not be verified.",
        CompatibilityProblem.WrongFirmware => "This firmware version has not been verified.",
        CompatibilityProblem.UnknownFiles => "The router's GL.iNet VPN system files could not be verified as supported.",
        _ => "Compatible"
    };
    public string CompatibilityDescription => problem switch
    {
        CompatibilityProblem.WrongDevice => $"Detected: {Router?.Model ?? "Unknown device"}. Installation supports GL-MT5000 only.",
        CompatibilityProblem.MissingVpn => "Create a VPN tunnel and add VPN connections to it, then disconnect and reconnect here.",
        CompatibilityProblem.InsufficientLocations => "Add connections to at least two different country/city locations within one VPN tunnel, then reconnect here.",
        CompatibilityProblem.InactiveVpn => vpnCheckFailures.Count == 0
            ? "The active VPN state could not be verified. Reconnect and try again."
            : string.Join(" ", vpnCheckFailures.Distinct(StringComparer.Ordinal)) + " Reconnect after resolving the reported issue.",
        CompatibilityProblem.UnreadableFirmware => "Check the router's firmware information in its Admin Panel, then reconnect. Installation cannot continue without a readable version.",
        CompatibilityProblem.WrongFirmware => $"Detected firmware: {Router?.Firmware ?? "Unknown"}. You can try continuing, but Hotswapper will still reject any unrecognized system-file contents before patching.",
        CompatibilityProblem.UnknownFiles => "One or more required firmware files could not be verified against a known stock or previously patched layout. The version override cannot bypass these checks.",
        _ => ""
    };
    public bool AcceptUnsupportedFirmware
    {
        get => acceptUnsupportedFirmware;
        set { if (Set(ref acceptUnsupportedFirmware, value)) RefreshPresentation(); }
    }

    public ObservableCollection<GuardIpEntry> GuardEntries { get; } = [];
    public bool HasGuards => GuardEntries.Count > 0;
    public string GuardHint => !HasGuards
        ? "No protected devices. Only the first reboot hour is needed."
        : "Only IP addresses with an existing DHCP reservation on this router can be used.";
    public string RebootStartText { get => rebootStartText; set { if (Set(ref rebootStartText, value)) RefreshPresentation(); } }
    public string RebootEndText { get => rebootEndText; set { if (Set(ref rebootEndText, value)) RefreshPresentation(); } }

    private void RefreshPresentation()
    {
        foreach (var p in new[] { nameof(Title), nameof(StepLabel), nameof(PrimaryLabel), nameof(ShowBack),
            nameof(ShowCancel), nameof(ShowPrimary), nameof(ShowConnect),
            nameof(ShowSaveLog), nameof(ConnectionButtonLabel), nameof(ConnectionSummary),
            nameof(Connected), nameof(IsDisconnected), nameof(CanConnect), nameof(CanToggleConnection),
            nameof(ShowVpnHelp), nameof(ShowFirmwareHelp), nameof(ShowFirmwareOverride), nameof(CompatibilityHeadline),
            nameof(CompatibilityDescription), nameof(HasGuards), nameof(GuardHint) }) Changed(p);
        BackCommand.Refresh(); PrimaryCommand.Refresh(); AddGuardCommand.Refresh();
    }
    private void SetConnection(bool value)
    {
        connected = value;
        RefreshPresentation();
    }
    private static int DistinctPlaces(VpnProfile p) => new ExactLocationResolver().Group(p.Connections)
        .Count(g => !g.Label.StartsWith("Unresolved peer ", StringComparison.Ordinal));
    private void EvaluateCompatibility()
    {
        // Order is intentional. Never replace a wrong-device error with a firmware error.
        problem = Router?.IsBrume != true ? CompatibilityProblem.WrongDevice
            : profileCount == 0 ? CompatibilityProblem.MissingVpn
            : locationProfileCount == 0 ? CompatibilityProblem.InsufficientLocations
            : EligibleProfiles.Count == 0 ? CompatibilityProblem.InactiveVpn
            : !Regex.IsMatch(Router.Firmware, @"^[0-9]+\.[0-9]+\.[0-9]+$") ? CompatibilityProblem.UnreadableFirmware
            : !firmwareFilesKnown || CompatibilityCatalog.Classify(Router.Rtp2Hash) is Compatibility.Unknown or Compatibility.KnownIncompatible
                ? CompatibilityProblem.UnknownFiles
            : !CompatibilityCatalog.TestedFirmware.Contains(Router.Firmware) ? CompatibilityProblem.WrongFirmware
            : CompatibilityProblem.None;
        RefreshPresentation();
    }
    private int profileCount, locationProfileCount;
    public async Task ConnectAsync(string password)
    {
        await RunAsync(async ct =>
        {
            if (string.IsNullOrWhiteSpace(password) && !demo) throw new SafeFailure("Enter the router administrator password.");
            session?.Dispose();
            session = null;
            ClearConnectionData();
            IRouterSession attempt = createSession();
            session = attempt;
            Status = "Connecting…";
            try
            {
                var identity = await attempt.ConnectAsync(demo ? "192.0.2.1" : RouterAddress.Trim(), password, ct);
                ct.ThrowIfCancellationRequested();
                if (identity.IsBrume)
                {
                    try
                    {
                        await attempt.VerifyFirmwareFilesAsync(identity, ct);
                        firmwareFilesKnown = true;
                    }
                    catch (SafeFailure) { } // Keep the connection open so the compatibility screen can explain the block.
                    var profiles = await attempt.ProfilesAsync(ct);
                    ct.ThrowIfCancellationRequested();
                    profileCount = profiles.Count;
                    foreach (var profile in profiles.Where(p => DistinctPlaces(p) >= 2))
                    {
                        locationProfileCount++;
                        try
                        {
                            await attempt.VerifyActiveProfileAsync(profile, ct);
                            EligibleProfiles.Add(profile);
                        }
                        catch (SafeFailure e)
                        {
                            vpnCheckFailures.Add(e.Message);
                        }
                    }
                    SelectedProfile = EligibleProfiles.FirstOrDefault();
                }
                Router = identity;
                session = attempt;
                SetConnection(true);
                EvaluateCompatibility();
                Status = problem == CompatibilityProblem.None ? "Connected. Ready to configure tiers." : "Connected. Check the compatibility notice.";
                Page = problem == CompatibilityProblem.None ? 3 : 2;
            }
            catch
            {
                attempt.Dispose();
                session = null;
                ClearConnectionData();
                throw;
            }
        });
    }
    private RouterIdentity? Router { get => router; set { router = value; RefreshPresentation(); } }
    private void ClearConnectionData()
    {
        Router = null; EligibleProfiles.Clear(); SelectedProfile = null; knownClients = [];
        foreach (var entry in GuardEntries) entry.PropertyChanged -= GuardChanged;
        GuardEntries.Clear();
        RebootStartText = ""; RebootEndText = "";
        profileCount = 0;
        locationProfileCount = 0;
        vpnCheckFailures.Clear();
        firmwareFilesKnown = false;
        problem = CompatibilityProblem.None;
        AcceptUnsupportedFirmware = false;
        SetConnection(false);
    }
    public void Disconnect()
    {
        if (Busy || Page != 1) return;
        session?.Dispose(); session = null;
        ClearConnectionData();
        ErrorMessage = "";
        Status = "Disconnected.";
    }
    private void Back()
    {
        if (Busy) return;
        ErrorMessage = "";
        Page = Page switch { 4 => 3, 3 => 1, 2 => 1, 1 => 0, _ => 0 };
    }
    private bool CanContinue()
    {
        if (Busy) return false;
        return Page switch
        {
            0 => true,
            1 => Connected,
            2 => Connected && problem == CompatibilityProblem.WrongFirmware && AcceptUnsupportedFirmware,
            3 => Connected && SelectedProfile != null && Tiers[1].Locations.Count > 0 && Tiers[2].Locations.Count > 0,
            4 => Connected && ValidHours() && ValidGuards(),
            _ => false
        };
    }
    private static bool Hour(string text, out int hour)
    {
        hour = 0;
        return text.Length == 2 && text.All(c => c is >= '0' and <= '9') &&
            int.TryParse(text, out hour) && hour is >= 0 and <= 23;
    }
    private bool ValidHours()
    {
        if (!Hour(RebootStartText, out var start)) return false;
        return !HasGuards || Hour(RebootEndText, out var end) && start <= end;
    }
    private bool ValidGuards()
    {
        if (GuardEntries.Count == 0) return true;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in GuardEntries)
        {
            if (!IPAddress.TryParse(entry.Address.Trim(), out var parsed) ||
                parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                !seen.Add(entry.Address.Trim()) ||
                !knownClients.Any(d => d.Reserved && d.Ip == entry.Address.Trim())) return false;
        }
        return true;
    }
    private void AddGuard()
    {
        var entry = new GuardIpEntry();
        entry.PropertyChanged += GuardChanged;
        GuardEntries.Add(entry);
        RefreshPresentation();
    }
    private void GuardChanged(object? sender, PropertyChangedEventArgs e) => RefreshPresentation();
    public void RemoveGuard(GuardIpEntry entry)
    {
        entry.PropertyChanged -= GuardChanged;
        GuardEntries.Remove(entry);
        if (!HasGuards) RebootEndText = "";
        RefreshPresentation();
    }
    private InstallerConfiguration Configuration()
    {
        var selected = SelectedProfile ?? throw new SafeFailure("Select an existing VPN tunnel.");
        if (!ValidHours()) throw new SafeFailure("Enter a valid reboot hour (00–23). With protected devices, enter both hours in ascending order.");
        if (!ValidGuards()) throw new SafeFailure("A reboot-blocking IP is invalid, duplicated or does not have an existing DHCP reservation on this router.");
        var guards = GuardEntries.Select(g => knownClients.First(c => c.Reserved && c.Ip == g.Address.Trim())).ToArray();
        var start = int.Parse(RebootStartText);
        var end = HasGuards ? int.Parse(RebootEndText) : start;
        return new InstallerConfiguration(Router ?? throw new SafeFailure("Connect to a Brume 3 first."), selected,
            Tiers.ToArray(), false, "", true, guards)
        {
            RebootWindowStart = start,
            RebootWindowEnd = end,
            AllowUnsupportedFirmware = problem == CompatibilityProblem.WrongFirmware && AcceptUnsupportedFirmware
        };
    }
    private async Task NextAsync(CancellationToken ct)
    {
        switch (Page)
        {
            case 0: Page = 1; Status = "Enter the router credentials."; return;
            case 1:
                EvaluateCompatibility(); Page = problem == CompatibilityProblem.None ? 3 : 2; return;
            case 2: Page = 3; Status = "Configure failover locations."; return;
            case 3:
                Status = "Reading reserved LAN addresses…";
                knownClients = await session!.ClientsAsync(ct);
                Page = 4; Status = "Set the reboot schedule and optional protected devices.";
                return;
            case 4:
                // PlanAsync still performs all real safety checks; no intermediate review screen.
                var config = Configuration();
                Page = 5; Progress.Clear(); InstallationHeadline = "Installing…"; Status = "Installation in progress.";
                Progress.Add("Checking router state and preparing installation…");
                log.Add("Checking router state and preparing installation…");
                try
                {
                    _ = await session!.PlanAsync(config, ct);
                    var progress = new Progress<string>(s => { Progress.Add(s); Status = s; log.Add(s); });
                    var result = await session.InstallAsync(config, progress, ct);
                    installed = result.Success;
                    foreach (var line in result.Checks) { Progress.Add(line); log.Add(line); }
                    InstallationHeadline = installed ? "Installation complete" : "Installation failed";
                    Status = installed ? "Hotswapper is installed. No synthetic failover was performed." : "Installation failed.";
                }
                catch (OperationCanceledException) { InstallationHeadline = "Installation cancelled"; throw; }
                catch (SafeFailure e) { InstallationHeadline = "Installation failed"; throw new SafeFailure(e.Message); }
                catch { InstallationHeadline = "Installation failed"; throw; }
                finally { session?.Dispose(); session = null; }
                return;
        }
    }
    private async Task RunAsync(Func<CancellationToken, Task> action)
    {
        if (Busy) return;
        ErrorMessage = "";
        using var cts = new CancellationTokenSource(); operation = cts; Busy = true;
        try { await action(cts.Token); }
        catch (OperationCanceledException)
        {
            Status = "Operation cancelled."; Progress.Add(Status); log.Add(Status);
            if (Page != 5) ErrorMessage = Status;
        }
        catch (SafeFailure e)
        {
            Status = e.Message; if (Page == 5) Progress.Add("ERROR: " + e.Message); log.Add("ERROR: " + e.Message);
            if (Page != 5) ErrorMessage = Status;
        }
        catch
        {
            Status = "Operation failed. See router state or try again. Sensitive details were withheld.";
            if (Page == 5) Progress.Add("ERROR: " + Status);
            log.Add("ERROR: " + Status);
            if (Page != 5) ErrorMessage = Status;
        }
        finally { Busy = false; operation = null; RefreshPresentation(); }
    }
    public void Move(VpnLocationGroup group, TierColumn target, int index)
    {
        if (Busy || Page != 3) return;
        var source = Tiers.Single(t => t.Locations.Contains(group));
        var old = source.Locations.IndexOf(group);
        if (source == target && old < index) index--;
        source.Locations.Remove(group);
        target.Locations.Insert(Math.Clamp(index, 0, target.Locations.Count), group);
        RefreshPresentation();
    }
    public void Dispose()
    {
        operation?.Cancel(); session?.Dispose(); session = null;
        foreach (var entry in GuardEntries) entry.PropertyChanged -= GuardChanged;
    }
}
