using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;

namespace BrumeHotswapper.Installer.Services;

// Earlier lookups may serve local destinations, but must not provide another exit.
public static class EarlierRouting
{
    public static async Task VerifyAsync(IRouterTransport router, string rules, string selected, uint mark, CancellationToken ct)
    {
        int priority = int.Parse(selected.Split(':')[0].Trim());
        string? allRoutes = null, lan = null;
        foreach (var line in rules.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var head = Regex.Match(line.Trim(), @"^(\d+):\s+(.+)$");
            if (!head.Success) throw Unsupported();
            if (int.Parse(head.Groups[1].Value) > priority || line == selected) continue;
            string body = head.Groups[2].Value;
            var rule = Regex.Match(body, @"^(not )?from all(?: (?:iif|oif) [\w.-]+)?(?: fwmark (0x[0-9a-fA-F]+|[0-9]+)(?:/(0x[0-9a-fA-F]+|[0-9]+))?)? lookup ([\w-]+)(?: suppress_prefixlength ([0-9]+))?$");
            if (!rule.Success) throw Unsupported();
            bool inverted = rule.Groups[1].Success;
            if (rule.Groups[2].Success)
            {
                uint value = Number(rule.Groups[2].Value);
                uint mask = rule.Groups[3].Success ? Number(rule.Groups[3].Value) : uint.MaxValue;
                // Only the slot bits are established here. Other mark bits may vary.
                bool disjoint = ((value ^ mark) & mask & 0xf000) != 0;
                bool alwaysMatches = (mask & ~0xf000u) == 0 && !disjoint;
                if ((!inverted && disjoint) || (inverted && alwaysMatches && !body.Contains("iif ") && !body.Contains("oif "))) continue;
            }
            else if (inverted) throw Unsupported();
            string table = CanonicalTable(rule.Groups[4].Value);
            int suppress = rule.Groups[5].Success ? int.Parse(rule.Groups[5].Value) : -1;
            if (suppress > 32) throw Unsupported();
            // Reading all tables also handles empty/nonexistent tables without
            // interpreting a failed per-table dump as an empty routing table.
            allRoutes ??= await router.ExecuteAsync("ip -4 route show table all", ct);
            foreach (var route in allRoutes.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var tableField = Regex.Match(route, @"\btable ([\w-]+)\b");
                if (CanonicalTable(tableField.Success ? tableField.Groups[1].Value : "main") != table) continue;
                string clean = Regex.Replace(route.Trim(), @"\s+table [\w-]+", "");
                if (Regex.IsMatch(clean, @"^(blackhole|unreachable|prohibit) ")) continue;
                if (Regex.IsMatch(clean, @"^local ") && !Regex.IsMatch(clean, @"\b(via|nexthop|encap)\b")) continue;
                if (table == "local" && Regex.IsMatch(clean, @"^broadcast \S+ dev [\w.-]+ proto kernel scope link(?: |$)") &&
                    !Regex.IsMatch(clean, @"\b(via|nexthop|encap)\b")) continue;
                var destination = clean.Split(' ')[0];
                int prefix = Prefix(destination);
                if (prefix < 0) throw Unsupported();
                // Linux suppresses routes with prefix length <= this value.
                if (prefix <= suppress) continue;
                lan ??= await router.ExecuteAsync("ubus call network.interface.lan status", ct);
                if (!LocalRoute(clean, lan)) throw Unsupported();
            }
        }
    }

    private static uint Number(string value) => value.StartsWith("0x") ? Convert.ToUInt32(value[2..], 16) : uint.Parse(value);
    private static string CanonicalTable(string table) => table switch { "255" => "local", "254" => "main", "253" => "default", _ => table };
    private static int Prefix(string destination)
    {
        if (destination == "default") return 0;
        var parts = destination.Split('/');
        if (!IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return -1;
        return parts.Length == 1 ? 32 : parts.Length == 2 && int.TryParse(parts[1], out int n) && n is >= 0 and <= 32 ? n : -1;
    }
    public static bool LocalRoute(string route, string status)
    {
        // Require kernel evidence of a connected route plus authoritative LAN
        // interface/address discovery. No interface name or subnet is assumed.
        var match = Regex.Match(route, @"^(\S+) dev ([\w.-]+) proto kernel scope link(?: src ([0-9.]+))?(?: metric [0-9]+)?(?: linkdown)?$");
        if (!match.Success || Prefix(match.Groups[1].Value) <= 0) return false;
        try
        {
            using var json = JsonDocument.Parse(status);
            var root = json.RootElement;
            if (!root.GetProperty("up").GetBoolean() || root.GetProperty("l3_device").GetString() != match.Groups[2].Value) return false;
            foreach (var address in root.GetProperty("ipv4-address").EnumerateArray())
            {
                string ip = address.GetProperty("address").GetString()!;
                int prefix = address.GetProperty("mask").GetInt32();
                if (prefix is < 1 or > 32 || prefix != Prefix(match.Groups[1].Value)) continue;
                if (match.Groups[3].Success && match.Groups[3].Value != ip) continue;
                uint mask = uint.MaxValue << (32 - prefix);
                if ((Address(ip) & mask) == Address(match.Groups[1].Value.Split('/')[0])) return true;
            }
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) { }
        return false;
    }
    private static uint Address(string text)
    {
        var bytes = IPAddress.Parse(text).GetAddressBytes();
        if (bytes.Length != 4) throw new FormatException();
        return (uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3];
    }
    private static SafeFailure Unsupported() => new("An earlier routing rule is ambiguous or can bypass the selected VPN. Only verified local/LAN routes are allowed before it.");
}
