using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
public static class RoutingProtection
{
    // A selected policy constrains the 0xf000 bits; all other packet mark bits remain unknown.
    public static bool CanMatch(string rule, uint selected)
    {
        var m = Regex.Match(rule, @"\bfwmark (0x[0-9a-fA-F]+|[0-9]+)(?:/(0x[0-9a-fA-F]+|[0-9]+))?(?:\s|$)");
        if (!m.Success || Regex.IsMatch(rule, @"\bnot\b")) return true;
        static uint Number(string s) => s.StartsWith("0x") ? Convert.ToUInt32(s[2..], 16) : uint.Parse(s);
        try {
            uint value = Number(m.Groups[1].Value), mask = m.Groups[2].Success ? Number(m.Groups[2].Value) : uint.MaxValue;
            return ((selected ^ value) & mask & 0xf000u) == 0;
        } catch (Exception e) when (e is FormatException or OverflowException) { return true; }
    }
    public static bool SafeRoutes(string routes, string active, bool suppressDefault = false)
    {
        foreach (var line in routes.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()))
        {
            if (suppressDefault && Regex.IsMatch(line, @"^(?:(?:unreachable|blackhole|prohibit|throw) )?default(?: |$)")) continue;
            if (Regex.IsMatch(line, @"^(unreachable|blackhole|prohibit) ")) continue;
            if (Regex.IsMatch(line, @"^(local|broadcast) ")) continue; // host delivery, never a WAN forward
            if (Regex.IsMatch(line, @"^(throw|unicast|nat|multicast) ")) return false;
            if (!Regex.IsMatch(line, $@"\bdev {Regex.Escape(active)}(?: |$)")) return false;
            if (Regex.IsMatch(line, @"\b(via|nexthop|encap)\b")) return false;
        }
        return true;
    }
    public static async Task<bool> EarlierRulesSafeAsync(IRouterTransport router, string rules, string selectedRule, int priority, uint mark, string active, CancellationToken ct)
    {
        if (rules.Split('\n').Count(line => line == selectedRule) != 1) return false;
        foreach (var line in rules.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parsed = Regex.Match(line, @"^\s*(\d+):\s+(.*)$");
            if (!parsed.Success || !int.TryParse(parsed.Groups[1].Value, out int p)) return false;
            if (p > priority || line == selectedRule) continue;
            string body = parsed.Groups[2].Value.Trim();
            if (body == "from all lookup local") continue;
            if (!CanMatch(body, mark)) continue;
            // Equal-priority applicable lookups remain ambiguous, even if table contents look safe.
            if (p == priority) return false;
            if (Regex.IsMatch(body, @"^from all (blackhole|unreachable|prohibit)$")) continue;
            // Earlier conditional lookups may apply to a subset. Inspect their entire table conservatively.
            var lookup = Regex.Match(body, @"^from (?:all|[0-9./]+)(?: iif [A-Za-z0-9_.-]+)? lookup ([A-Za-z0-9_]+)( suppress_prefixlength 0)?$");
            if (!lookup.Success) return false;
            string routes;
            try { routes = await router.ExecuteAsync("ip -4 route show table " + lookup.Groups[1].Value, ct); }
            catch (OperationCanceledException) { throw; }
            catch { throw new SafeFailure("Required earlier routing-table evidence is unavailable. Kill-switch routing safety cannot be established."); }
            if (!SafeRoutes(routes, active, lookup.Groups[2].Success)) return false;
        }
        return true;
    }
}
