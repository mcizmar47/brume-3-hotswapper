using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;
public sealed partial class Runner
{
    private async Task FirmwareChecksAsync(RouterIdentity identity, CancellationToken ct)
    {
        report(new("Live firmware SHA", Regex.IsMatch(identity.Rtp2Hash, "^[a-f0-9]{64}$") ? "PASS" : "BLOCK", Regex.IsMatch(identity.Rtp2Hash, "^[a-f0-9]{64}$") ? identity.Rtp2Hash : "Unrecognized hash format."));
        await Step("Firmware marker/anchor", async () =>
        {
            var marker = (await read.ExecuteAsync("grep -Fc '# vpn-watch GL reconciliation guard v1' /usr/bin/rtp2.sh || true", ct)).Trim();
            var anchor = (await read.ExecuteAsync("grep -Fxc 'cmd=\"$1\";shift' /usr/bin/rtp2.sh || true", ct)).Trim();
            Add("Firmware marker/anchor", marker == "1" && anchor == "1", $"Unique guard marker: {marker == "1"}; unique anchor: {anchor == "1"}.");
        });
        await Step("Firmware syntax", async () => { await read.ExecuteAsync("sh -n /usr/bin/rtp2.sh", ct); Add("Firmware syntax", true, "Syntax-only check passed; firmware not executed."); });
        await Step("SFTP diagnostics", async () =>
        {
            var diagnostic = await session.ProbeFirmwareSftpAsync(ct);
            report(new("SFTP diagnostics", diagnostic.StartsWith("SFTP connect,") ? "PASS" : "WARN", diagnostic + " Installation uploads still require verified SFTP capability."));
        });
        await Step("Firmware bytes", async () => await FirmwareAsync(identity, ct));
    }
    public async Task RunFollowUpAsync(RouterIdentity identity, CancellationToken ct)
    {
        Add("Connection identity consistency", identity.IsBrume && identity.Firmware == "4.9.0", "Rechecked identity/version for this new session; previously proven full discovery is not repeated.");
        if (!identity.IsBrume) return;
        await FirmwareChecksAsync(identity, ct);
        foreach (string path in DeploymentPlanning.Paths)
            await Step("File " + path, async () => { foreach (var item in MetadataReview.Evaluate(path, await read.ExecuteAsync(ReadOnlyTransport.FileMetadata(path), ct))) report(item); });
        await Step("Routing follow-up", async () =>
        {
            var policies = await read.ExecuteAsync(ReadOnlyTransport.Policies, ct);
            var candidates = new List<VpnProfile>();
            foreach (var row in policies.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var pair = row.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (pair.Length != 2 || !RouterInspection.IsPolicyIdentifier(pair[0]) || !Regex.IsMatch(pair[1], "^[0-9]+$")) continue;
                var group = (await read.ExecuteAsync($"uci -q get route_policy.{RouterInspection.Identifier(pair[0])}.group_id || true", ct)).Trim();
                if (Regex.IsMatch(group, "^[0-9]+$")) candidates.Add(new(pair[1], group, [], pair[0]));
            }
            if (candidates.Count != 1) throw new SafeFailure("Selected policy consistency is ambiguous; no broad rediscovery or guessed selection performed.");
            var profile = candidates[0];
            var key = RouterInspection.Identifier(profile.PolicySection);
            var mark = (await read.ExecuteAsync($"uci -q get route_policy.{key}.mark", ct)).Trim();
            var active = (await read.ExecuteAsync($"uci -q get route_policy.{key}.via", ct)).Trim();
            if (!Regex.IsMatch(mark, "^0x[0-9a-fA-F]{1,8}$") || !Regex.IsMatch(active, "^wgclient[123]$")) throw new SafeFailure("Selected routing mark/interface has an unsupported format.");
            report(new("Selected routing mark", "PASS", "Mark " + mark + "; active slot " + active + "; policy/provider identifiers withheld."));
            var intent = (await read.ExecuteAsync($"uci -q get route_policy.{key}.killswitch || true", ct)).Trim();
            Add("Layer A: configured intent", intent == "1", intent == "1" ? "Kill switch remains enabled." : "Kill-switch setting not verified enabled.");
            var chain = "TUNNEL" + profile.TunnelId + "_ROUTE_POLICY";
            var rules = await read.ExecuteAsync($"iptables -w -t mangle -S {chain}", ct);
            report(new("Selected tunnel chain shape", "WARN", RoutingEvidence.Sanitize(rules)));
            Add("Layer B: MARK/DROP", KillSwitchVerifier.HasPolicyRules(rules, chain, mark), "Evaluated exact paired marking/DROP scopes using the production parser.");
            await Step("Layer B: chain attachment", async () => { await read.ExecuteAsync($"iptables -w -t mangle -C ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j {chain}", ct); Add("Layer B: chain attachment", true, "Expected attachment exists."); });
            report(new("ROUTE_POLICY shape", "WARN", RoutingEvidence.Sanitize(await read.ExecuteAsync("iptables -w -t mangle -S ROUTE_POLICY", ct))));
            var policyRules = await read.ExecuteAsync("ip -4 rule show", ct);
            report(new("IPv4 policy-rule shapes", "WARN", RoutingEvidence.Sanitize(policyRules)));
            var tables = RoutingEvidence.SelectedTables(policyRules, mark);
            report(new("Selected lookup candidates", "WARN", tables.Count + " selected-mark table(s) found by diagnostic parser. This parser does not grant compatibility."));
            int index = 0;
            foreach (var table in tables)
            {
                var routes = await read.ExecuteAsync($"ip -4 route show table {table}", ct);
                report(new("Selected routing table " + (++index), "WARN", "Table identifier format: " + (Regex.IsMatch(table, "^[0-9]+$") ? "numeric" : "named") + ". " + RoutingEvidence.Sanitize(routes)));
            }
            report(new("Active-slot route shapes", "WARN", RoutingEvidence.Sanitize(await read.ExecuteAsync($"ip -4 route show table all dev {active}", ct))));
            await Step("Layer C: production verifier", async () => { await new KillSwitchVerifier().VerifyAsync(read, profile.PolicySection, ct); Add("Layer C: production verifier", true, "Existing complete verifier accepted this snapshot; no rule changes made."); });
            Add("Routing snapshot consistency", mark == (await read.ExecuteAsync($"uci -q get route_policy.{key}.mark", ct)).Trim() && active == (await read.ExecuteAsync($"uci -q get route_policy.{key}.via", ct)).Trim(), "Rechecked selected mark/interface after collection; no transitions requested.");
        });
    }
}
public static class RoutingEvidence
{
    public static IReadOnlyList<string> SelectedTables(string rules, string mark)
    {
        uint selected = Convert.ToUInt32(mark[2..], 16);
        var tables = new HashSet<string>();
        foreach (var line in rules.Split('\n'))
        {
            if (Regex.IsMatch(line, @"\bnot\b")) continue;
            var m = Regex.Match(line, @"\bfwmark (0x[0-9a-fA-F]+|[0-9]+)(?:/(0x[0-9a-fA-F]+|[0-9]+))?\s+lookup ([A-Za-z0-9_]+)\b");
            if (!m.Success) continue;
            static uint Number(string s) => s.StartsWith("0x") ? Convert.ToUInt32(s[2..], 16) : uint.Parse(s);
            if (!uint.TryParse(m.Groups[1].Value.StartsWith("0x") ? Convert.ToUInt32(m.Groups[1].Value[2..],16).ToString() : m.Groups[1].Value, out uint value)) continue;
            uint mask = m.Groups[2].Success ? Number(m.Groups[2].Value) : uint.MaxValue;
            if ((selected & mask) == (value & mask)) tables.Add(m.Groups[3].Value);
        }
        return tables.ToArray();
    }
    public static string Sanitize(string source)
    {
        var text = Regex.Replace(source, @"--comment\s+(?:""[^""]*""|'[^']*'|\S+)", "--comment [withheld]");
        text = Regex.Replace(text, @"https?://\S+", "[URL withheld]");
        text = Regex.Replace(text, @"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b", "[IPv4]");
        text = Regex.Replace(text, @"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", "[MAC]");
        text = Regex.Replace(text, @"TUNNEL[0-9]+", "TUNNEL<id>");
        text = Regex.Replace(text, @"(?:dst_net|src_net)[0-9]+", "policy_set<id>");
        text = Regex.Replace(text, @"(?<=--match-set )[^\s]+", "[set]");
        text = Regex.Replace(text, @"(?<=lookup )[^\s]+", m => Regex.IsMatch(m.Value, @"^(?:[0-9]+|main|local|default|wgclient[123])$") ? m.Value : "[named-table]");
        text = Regex.Replace(text, @"(?<=table )[^\s]+", m => Regex.IsMatch(m.Value, @"^(?:[0-9]+|main|local|default|wgclient[123])$") ? m.Value : "[named-table]");
        text = Regex.Replace(text, @"(?<=dev )[^\s]+", m => Regex.IsMatch(m.Value, @"^(?:wgclient[123]|eth[0-9]+|br-lan|lo)$") ? m.Value : "[interface]");
        text = Regex.Replace(text, @"(?<=-A )[^\s]+|(?<=-N )[^\s]+|(?<=-j )[^\s]+|(?<=-g )[^\s]+", m => Regex.IsMatch(m.Value, @"^(?:ROUTE_POLICY|TUNNEL<id>_ROUTE_POLICY|MARK|CONNMARK|DROP|RETURN|ACCEPT)$") ? m.Value : "[chain]");
        return text.Trim();
    }
}
