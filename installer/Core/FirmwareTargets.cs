using System.IO;
using System.Text.RegularExpressions;
namespace BrumeHotswapper.Installer.Core;

public sealed record FirmwareTarget(string Id, string Path, string StockHash, string PatchedHash)
{
    public bool Supports(string hash) => hash == StockHash || hash == PatchedHash ||
        (Id == "rtp" && hash == "84339bc25c130a0c2b31dae698bae1b224d0fc58074964a0ade37a8b84b060e1") ||
        (Id == "instances" && hash == "184793a110dc0c728fa18f5857ea05d3f5efb432b142ac89da50cd8708bc909d") ||
        (Id == "setup" && hash == "0e727b62335ece0338db37b80ec781ca703b203bc1910983713636a8cfee61b5") ||
        (Id == "proto" && hash == "fb6ca0fa6406c13bd68556f3fdcad775c56fe9620330d6878a6172947bae91c6") ||
        (Id == "firewall_event" && hash == "0f9a66e076dfd530c0a1748652442503dc3a0557fed42daab2c59f170d283406") ||
        (Id == "firewall" && hash == "5b4a449f28dbbcf5effa07a61d67376851c7a9db8d29a39b8cef0a82105cda38") ||
        (Id == "rtp" && hash == CompatibilityCatalog.PreviousGuardHash) ||
        (Id == "firewall" && hash == "7994c173df797620dc1f31ffef593dc43db70982da10c2f190f98e6cf89875db");
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
