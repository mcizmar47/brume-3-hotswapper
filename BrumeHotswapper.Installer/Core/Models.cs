using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BrumeHotswapper.Installer.Core;

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    protected void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    { if (EqualityComparer<T>.Default.Equals(field, value)) return false; field = value; Changed(name); return true; }
}
public enum Compatibility { StockKnownCompatible, AlreadyPatchedKnownCompatible, HistoricalGuardKnownCompatible, Unknown, KnownIncompatible }
public record RouterIdentity(string Address, string Model, string Board, string Firmware, string Rtp2Hash)
{
    public bool IsBrume => Board.Equals("glinet,gl-mt5000", StringComparison.OrdinalIgnoreCase)
        || Model.Equals("GL.iNet GL-MT5000", StringComparison.OrdinalIgnoreCase)
        || Model.Equals("GL-MT5000", StringComparison.OrdinalIgnoreCase);
}
public record VpnConnection(string PeerId, string Name, string Location);
public record VpnProfile(string TunnelId, string GroupId, IReadOnlyList<VpnConnection> Connections, string PolicySection = "")
{
    public string Display => $"VPN list {GroupId} · {Connections.Count} connections";
}
public record VpnLocationGroup(string Id, string Label, IReadOnlyList<VpnConnection> Connections)
{
    public string CountLabel => $"{Connections.Count} connection{(Connections.Count == 1 ? "" : "s")}";
}
public class TierColumn(string title, int tier)
{
    public string Title { get; } = title;
    public int Tier { get; } = tier;
    public ObservableCollection<VpnLocationGroup> Locations { get; } = [];
}
public class LanClient(string hostname, string ip, string mac, bool reserved = false) : Observable
{
    private bool selected;
    public string Hostname { get; } = hostname;
    public string Ip { get; } = ip;
    public string Mac { get; } = mac;
    public bool Reserved { get; } = reserved;
    public bool Selected { get => selected; set => Set(ref selected, value); }
    public string Display => $"{Hostname}   {Ip}   {Mac}" + (Reserved ? "   (reserved)" : "");
}
public record Reservation(string Section, string Mac, string Ip);
public record ReservationChange(string Mac, string Ip, bool Create);
public record InstallerConfiguration(RouterIdentity Router, VpnProfile Profile, IReadOnlyList<TierColumn> Tiers,
    bool Notifications, string NtfyUrl, bool Maintenance, IReadOnlyList<LanClient> Guards)
{
    public override string ToString() => "Installer configuration (private values omitted)";
}
public record InstallationStep(string Name, bool ChangesRouter);
public record InstallationResult(bool Success, IReadOnlyList<string> Checks);
public class SafeFailure(string message) : Exception(message);
