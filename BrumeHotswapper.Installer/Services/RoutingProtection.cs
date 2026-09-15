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
    public static bool SafeRoutes(string routes, string active, bool suppressDefault = false, VerifiedLanLink? lan = null)
    {
        foreach (var line in routes.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()))
        {
            if (suppressDefault && Regex.IsMatch(line, @"^(?:(?:unreachable|blackhole|prohibit|throw) )?default(?: |$)")) continue;
            if (Regex.IsMatch(line, @"^(unreachable|blackhole|prohibit) ")) continue;
            if (Regex.IsMatch(line, @"^(local|broadcast) ")) continue; // host delivery, never a WAN forward
            if (Regex.IsMatch(line, @"^(throw|unicast|nat|multicast) ")) return false;
            if (lan?.ContainsDirectRoute(line) == true) continue;
            if (!Regex.IsMatch(line, $@"\bdev {Regex.Escape(active)}(?: |$)")) return false;
            if (Regex.IsMatch(line, @"\b(via|nexthop|encap)\b")) return false;
        }
        return true;
    }
    public static bool ProvesEmptyTable(string dump,string table)
    {
        if (!Regex.IsMatch(table,@"\A[0-9]+\z") || table is "253" or "254" or "255") return false;
        foreach (var row in dump.Split('\n',StringSplitOptions.RemoveEmptyEntries))
        {
            // Reject partial/unsupported renderings and unresolved table aliases rather than
            // mistaking missing text for evidence of an empty FIB table.
            if (!Regex.IsMatch(row.Trim(),@"\A(?:(?:local|broadcast|unreachable|blackhole|prohibit|throw|unicast) )?(?:default|(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]+)?)(?: |$)")) return false;
            var id=Regex.Match(row,@"\btable (\S+)");
            if (!id.Success) continue; // ip omits the main table identifier
            if (id.Groups[1].Value==table) return false;
            if (!Regex.IsMatch(id.Groups[1].Value,@"\A(?:[0-9]+|main|local|default)\z")) return false;
        }
        return true;
    }
    private static async Task<bool> ConfirmEmptyTableAsync(IRouterTransport router,string table,CancellationToken ct)
    {
        try {return ProvesEmptyTable(await router.ExecuteAsync("ip -4 route show table all",ct),table);}
        catch(OperationCanceledException){throw;}
        catch{return false;}
    }
    public static async Task<bool> EarlierRulesSafeAsync(IRouterTransport router, string rules, string selectedRule, int priority, uint mark, string active, CancellationToken ct)
    {
        if (rules.Split('\n').Count(line => line == selectedRule) != 1) return false;
        VerifiedLanLink? lan = null;
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
            catch {
                if (await ConfirmEmptyTableAsync(router,lookup.Groups[1].Value,ct)) continue;
                throw new SafeFailure($"Earlier RPDB priority {p} lookup requires table evidence: a complete readable table dump did not establish an empty lookup. Selected marked traffic could be affected.");
            }
            if (!SafeRoutes(routes, active, lookup.Groups[2].Success))
            {
                try { lan ??= await new RouterInspection(router,new KillSwitchVerifier()).LanLinkAsync(ct); }
                catch(OperationCanceledException){throw;}
                catch {throw new SafeFailure($"Earlier RPDB priority {p}: local-only LAN evidence could not be established for a non-VPN route.");}
                if (!SafeRoutes(routes, active, lookup.Groups[2].Success, lan))
                    throw new SafeFailure($"Earlier RPDB priority {p} lookup can use a WAN, unverified or unsupported route before the selected VPN table. " +
                        (lookup.Groups[2].Success ? "suppress_prefixlength 0 excludes default routes, not more-specific routes. " : "") +
                        "Only positively verified directly connected LAN routes are exempt.");
            }
        }
        return true;
    }
}
