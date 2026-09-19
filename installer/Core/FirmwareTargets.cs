using System.IO;
using System.Text.RegularExpressions;
namespace BrumeHotswapper.Installer.Core;

public sealed record FirmwareTarget(string Id, string Path, string StockHash, string PatchedHash)
{
    public bool Supports(string hash) => hash == StockHash || hash == PatchedHash ||
        (Id == "rtp" && hash == CompatibilityCatalog.PreviousGuardHash);
}

public static class FirmwareTargets
{
    public static readonly IReadOnlyList<FirmwareTarget> All = Load();
    public static FirmwareTarget? Find(string path) => All.FirstOrDefault(t => t.Path == path);
    private static IReadOnlyList<FirmwareTarget> Load()
    {
        var targets = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "RouterAssets", "gl-targets.tsv"))
            .Where(l => l.Length > 0).Select(l => l.Split('\t')).ToArray();
        if (targets.Length != 10 || targets.Any(f => f.Length != 4 ||
            !Regex.IsMatch(f[0], "^[a-z_]+$") || !Regex.IsMatch(f[1], "^/(usr/bin|lib/netifd/proto|etc/hotplug.d/(wireguard|iface)|etc/init.d)/[a-zA-Z0-9_.-]+$") ||
            !Regex.IsMatch(f[2], "^[a-f0-9]{64}$") || !Regex.IsMatch(f[3], "^[a-f0-9]{64}$")) ||
            targets.Select(f => f[1]).Distinct().Count() != targets.Length)
            throw new InvalidDataException("Invalid firmware target catalog.");
        return targets.Select(f => new FirmwareTarget(f[0], f[1], f[2], f[3])).ToArray();
    }
}
