using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;
public sealed partial class Runner
{
    private async Task FirmwareChecksAsync(RouterIdentity identity,CancellationToken ct)
    {
        await Step("Firmware compatibility",async()=>{
            await RouterPrerequisites.VerifyFirmwareAsync(read,identity,ct);
            Add("Firmware compatibility",true,CompatibilityCatalog.Classify(identity.Rtp2Hash)+"; shared catalog, hash, marker, anchor and syntax checks passed.");
        });
        await Step("Upload capability",async()=>{
            var kind=await session.ProbeUploadAsync(ct);
            Add("Upload capability",true,"Verified "+kind+" using the production transport probe; no router files created.");
        });
    }
    public async Task RunFollowUpAsync(RouterIdentity identity,CancellationToken ct)
    {
        Add("Identity/version",identity.IsBrume && CompatibilityCatalog.TestedFirmware.Contains(identity.Firmware),"Production authentication/identity result checked against the supported firmware catalog.");
        if(!identity.IsBrume)return;
        await FirmwareChecksAsync(identity,ct);
        await Step("Pending transaction",async()=>{await RouterPrerequisites.EnsureNoTransactionAsync(read,ct);Add("Pending transaction",true,"No pending transaction or lock.");});
        await Step("Required utilities",async()=>{await read.ExecuteAsync(RouterPrerequisites.CapabilitiesCommand,ct);Add("Required utilities",true,"Production command prerequisites passed.");});
        foreach(var path in DeploymentPlanning.Paths)
            await Step("File "+path,async()=>{
                var fields=await FileMetadata.ReadAsync(read,path,ct);
                var findings=MetadataReview.Evaluate(path,fields);
                if(findings.All(f=>f.Status=="PASS")) Add("File "+path,true,"Shared production metadata policy passed.");
                else foreach(var finding in findings.Where(f=>f.Status!="PASS")) report(finding);
            });
        await Step("VPN prerequisites",async()=>{
            var profiles=await new VpnDiscovery(read).DiscoverPoliciesAsync(ct);
            var profile=VpnDiscovery.AutoSelect(profiles)??throw new SafeFailure("A unique VPN policy was not established.");
            await new RouterInspection(read,new KillSwitchVerifier()).VerifyPolicySlotsAsync(profile,ct);
            Add("VPN prerequisites",true,"Shared policy/group, slot ownership and active-peer agreement checks passed.");
            await RoutingDiagnostics.VerifyAsync(read,profile.PolicySection,report,ct);
        });
    }
}
// Optional rendering only. Diagnostics never grant safety and never gate execution of the verifier.
public static class RoutingDiagnostics
{
    public static async Task CollectTablesAsync(IRouterTransport router,IEnumerable<string> tables,Action<Check> report,CancellationToken ct)
    {
        foreach(var table in tables.Where(t=>Regex.IsMatch(t,@"\A[A-Za-z0-9_]+\z")).Distinct())
        {
            try {var output=await router.ExecuteAsync("ip -4 route show table "+table,ct);report(new("Routing table diagnostic","WARN",RoutingEvidence.Sanitize(output)));}
            catch(OperationCanceledException){throw;}
            catch {report(new("Routing table diagnostic","WARN","Table unavailable or command returned nonzero; this diagnostic grants no safety result."));}
        }
    }
    public static async Task VerifyAsync(IRouterTransport router,string policy,Action<Check> report,CancellationToken ct)
    {
        try {
            await new KillSwitchVerifier().VerifyAsync(router,policy,ct);
            report(new("Kill switch and IPv6","PASS","Shared production verifier passed configured intent, firewall enforcement, routing protection and IPv6 prerequisites."));
            return;
        } catch(OperationCanceledException){throw;}
        catch(Exception e){report(new("Kill switch and IPv6","BLOCK",e is SafeFailure?e.Message:"Required safety evidence is unavailable; details withheld."));}
        // Dump only after failure. Each optional command is isolated from all others.
        try {
            var rules=await router.ExecuteAsync("ip -4 rule show",ct);
            report(new("Routing rule diagnostic","WARN",RoutingEvidence.Sanitize(rules)));
            var tables=Regex.Matches(rules,@"\blookup ([A-Za-z0-9_]+)\b").Select(m=>m.Groups[1].Value);
            await CollectTablesAsync(router,tables,report,ct);
        } catch(OperationCanceledException){throw;}
        catch {report(new("Routing diagnostics","WARN","Optional rule dump unavailable; production BLOCK remains authoritative."));}
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
