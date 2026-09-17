using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace BrumeHotswapper.Tests;
public class SecondPassTests
{
    internal static InstallerConfiguration Config(string hash = CompatibilityCatalog.StockHash)
    {
        var peers = new[] {new VpnConnection("11","VPN connection","Germany,Frankfurt")};
        var tiers = new[] { new TierColumn("Unassigned",0), new TierColumn("Tier 1",1), new TierColumn("Tier 2",2), new TierColumn("Tier 3",3) };
        tiers[1].Locations.Add(new ExactLocationResolver().Group(peers)[0]);
        return new(new("192.0.2.1","GL.iNet GL-MT5000","glinet,gl-mt5000","4.9.0",hash),new("42","7",peers,"vpn"),tiers,false,"",false,[]);
    }
    [Theory]
    [InlineData(CompatibilityCatalog.StockHash, Compatibility.StockKnownCompatible)]
    [InlineData(CompatibilityCatalog.PatchedHash, Compatibility.AlreadyPatchedKnownCompatible)]
    [InlineData("unknown", Compatibility.Unknown)]
    public void DistinctGuardStates(string hash, Compatibility expected) => Assert.Equal(expected,CompatibilityCatalog.Classify(hash));
    [Fact] public void BlacklistedHashStops()
    {
        const string hash="unit-test-incompatible";
        CompatibilityCatalog.IncompatibleHashes.Add(hash);
        try { Assert.Throws<SafeFailure>(() => ConfigurationGenerator.Validate(Config(hash))); }
        finally { CompatibilityCatalog.IncompatibleHashes.Remove(hash); }
    }
    [Fact] public void CommaLocationsNormalizeWithoutWorldMap()
    {
        var groups = new ExactLocationResolver().Group([new("1","unused"," Fictionland , Example City "),new("2","unused","Fictionland,Example City")]);
        var group=Assert.Single(groups); Assert.Equal("Fictionland / Example City",group.Label); Assert.Equal(2,group.Connections.Count);
    }
    [Fact] public void DifferentLocationsDoNotFuzzyMerge()
    {
        Assert.Equal(2,new ExactLocationResolver().Group([new("1","","Austria,Vienna"),new("2","","Australia,Vienna")]).Count);
    }
    [Theory]
    [InlineData("192.0.2.20",true)][InlineData("192.0.3.20",false)][InlineData("192.0.2.0",false)]
    [InlineData("192.0.2.255",false)][InlineData("192.0.2.1",false)]
    public void ReservationsStayInUsableSubnet(string ip,bool expected) => Assert.Equal(expected,new LanNetwork("192.0.2.1","255.255.255.0",100,100).ContainsHost(ip));
    [Fact] public void NewReservationIsMinimal()
    {
        var d=new LanClient("PC","192.0.2.20","02:00:00:00:00:20");
        Assert.True(Assert.Single(DhcpPlanner.Plan([d],[],[d],"192.0.2.1")).Create);
        Assert.Equal("hotswap_020000000020",RouterInstaller.ReservationSection(d.Mac));
    }
    [Fact] public void ZeroAndMultipleGuards()
    {
        Assert.Empty(ConfigurationGenerator.Guards(Config()));
        var c=Config() with {Guards=[new("PC","192.0.2.20","02:00:00:00:00:20"),new("Laptop","192.0.2.21","02:00:00:00:00:21")]};
        Assert.Equal(2,ConfigurationGenerator.Guards(c).Split('\n',StringSplitOptions.RemoveEmptyEntries).Length);
    }
    [Fact] public void RollbackPreservesConcurrentUnrelatedCron()
    {
        string current=CronPlanner.Supervisor+"\n"+CronPlanner.Maintenance+"\n22 2 * * * /root/new-user-job\n";
        string restored=DeploymentPlanning.RestoreOwnedCron(current,CronPlanner.Supervisor+"\n");
        Assert.DoesNotContain(CronPlanner.Maintenance,restored); Assert.Contains("/root/new-user-job",restored); Assert.Contains(CronPlanner.Supervisor,restored);
    }
    [Fact] public void RuntimeClassificationChecksActualPeerAndRoles()
    {
        var c=Config();
        const string good="current_iface=wgclient1\ncurrent_peer=11\ncurrent_rank=1\ncurrent_tier=1\ndowntier_iface=\ndowntier_peer=\nuptier_iface=\n";
        Assert.True(RuntimeValidation.IsHealthy(good,c));
        Assert.False(RuntimeValidation.IsHealthy(good.Replace("current_peer=11","current_peer=999"),c));
        Assert.False(RuntimeValidation.IsHealthy(good.Replace("uptier_iface=","uptier_iface=wgclient1"),c));
    }
    [Fact] public async Task RealTransactionCanCompleteWithVerifiedPreconditions()
    {
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new KillSwitchVerifier());
        var plan=await installer.PlanAsync(Config(),CancellationToken.None);
        var result=await installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None);
        Assert.True(result.Success); Assert.Equal(7,fake.Installed.Count); Assert.True(fake.Running);
        Assert.Equal(CronPlanner.Supervisor+"\n",fake.Cron); Assert.Equal(1,fake.RealPatches);
    }
    [Fact] public async Task PatchedFirmwareIsANoOpOnReinstall()
    {
        var fake=new RouterFixture { FirmwareHash=CompatibilityCatalog.PatchedHash };
        var installer=new RouterInstaller(fake,new VerifiedKillSwitch());
        var plan=await installer.PlanAsync(Config(CompatibilityCatalog.PatchedHash),CancellationToken.None);
        Assert.Contains("Already installed",plan.GuardAction);
        await installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None);
        Assert.Equal(0,fake.RealPatches);
    }
    [Fact] public async Task ReinstallDoesNotDuplicateSchedulesFilesOrPatches()
    {
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new VerifiedKillSwitch());
        await installer.InstallAsync(await installer.PlanAsync(Config(),CancellationToken.None),new Progress<string>(),CancellationToken.None);
        var plan=await installer.PlanAsync(Config(CompatibilityCatalog.PatchedHash),CancellationToken.None);
        Assert.All(plan.Snapshot.Files, f=>Assert.True(f.Exists));
        await installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None);
        Assert.Equal(7,fake.Installed.Count); Assert.Equal(1,fake.RealPatches); Assert.Equal(CronPlanner.Supervisor+"\n",fake.Cron);
    }
    [Fact] public async Task FailedKillSwitchMakesNoWrites()
    {
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new FailedKillSwitch());
        await Assert.ThrowsAsync<SafeFailure>(()=>installer.PlanAsync(Config(),CancellationToken.None));
        var plan=await new RouterInstaller(fake,new VerifiedKillSwitch()).PlanAsync(Config(),CancellationToken.None);
        await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None));
        Assert.Empty(fake.Uploads); Assert.Empty(fake.Installed);
    }
    [Fact] public async Task GuardFailureRollsBackOnlyOwnedFiles()
    {
        var fake=new RouterFixture {RejectPatch=true, Cron="22 2 * * * /root/unrelated\n"};
        var installer=new RouterInstaller(fake,new VerifiedKillSwitch());
        var plan=await installer.PlanAsync(Config(),CancellationToken.None);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>installer.InstallAsync(plan,new Progress<string>(),CancellationToken.None));
        Assert.Contains("rolled back",error.Message); Assert.Empty(fake.Installed);
        Assert.Contains("/root/unrelated",fake.Cron); Assert.DoesNotContain(CronPlanner.Supervisor,fake.Cron);
    }
    [Fact] public async Task PrivateUrlNeverAppearsInPlanOrStatus()
    {
        var c=Config() with {Notifications=true,NtfyUrl="https://ntfy.sh/synthetic-test-topic"};
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new VerifiedKillSwitch());
        var plan=await installer.PlanAsync(c,CancellationToken.None);
        Assert.DoesNotContain(c.NtfyUrl,plan.ToString()); Assert.DoesNotContain(c.NtfyUrl,c.ToString());
        Assert.All(plan.Changes,s=>Assert.DoesNotContain(c.NtfyUrl,s));
    }
    internal sealed class VerifiedKillSwitch : IKillSwitchVerifier
    { public Task VerifyAsync(IRouterTransport r,string policy,CancellationToken ct)=>Task.CompletedTask; }
    private sealed class FailedKillSwitch : IKillSwitchVerifier
    { public Task VerifyAsync(IRouterTransport r,string policy,CancellationToken ct)=>throw new SafeFailure("Kill switch is not verified."); }

    // In-memory command boundary fixture: never invokes SSH, SFTP or a shell.
    internal sealed class RouterFixture : IRouterTransport
    {
        private static string NormalizePaths(string value) => Regex.Replace(Regex.Replace(value, @"/run-[a-f0-9]{32}", "/run"), @"\.hotswap-(new|restore)-[a-f0-9]{32}", ".hotswap-$1");
        public Dictionary<string,string> Uploads {get;}=[];
        public Dictionary<string,string> Installed {get;}=[];
        public string FirmwareHash=CompatibilityCatalog.StockHash;
        public Dictionary<string,string> Backups {get;}=[];
        public string Cron="";
        public bool Running,RejectPatch;
        public int RealPatches;
        private static string Hash(string s)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        public Task UploadAsync(string path,string content,CancellationToken ct) {ct.ThrowIfCancellationRequested();Uploads[NormalizePaths(path)]=content;return Task.CompletedTask;}
        public Task<string> ExecuteAsync(string cmd,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            cmd=NormalizePaths(cmd);
            string result="";
            var metadata = DeploymentPlanning.Paths.SelectMany(p => FileMetadata.Commands(p).Select(f => (Path:p, Field:f.Key, Command:f.Value))).FirstOrDefault(f => f.Command == cmd);
            if (metadata.Command != null) {
                bool exists = metadata.Path == "/usr/bin/rtp2.sh" || Installed.ContainsKey(metadata.Path);
                result = metadata.Field switch {
                    "symlink" => "0", "exists" => exists ? "1" : "0", "regular" or "readable" => "1",
                    "listing" => (metadata.Path == "/usr/bin/rtp2.sh" ? "-rwxr-xr-x" : metadata.Path.EndsWith(".sh") ? "-rwx------" : "-rw-------") + " 1 0 0 123 Jan 1 00:00 " + metadata.Path,
                    "size" => "123", "sha256" => metadata.Path == "/usr/bin/rtp2.sh" ? FirmwareHash : Hash(Installed[metadata.Path]), _ => ""
                };
            }
            else if(cmd=="ubus call system board") result="{\"model\":\"GL.iNet GL-MT5000\",\"board_name\":\"glinet,gl-mt5000\"}";
            else if(cmd.StartsWith("sha256sum /usr/bin/rtp2.sh")) result=FirmwareHash;
            else if(cmd.StartsWith("sha256sum /root/hotswapper/installer/run/rtp2.preview")) result=CompatibilityCatalog.PatchedHash;
            else if(cmd is "uci -q get route_policy.vpn.killswitch || true" or "uci -q get route_policy.vpn.enabled || true") result="1";
            else if(cmd=="uci -q get glipv6.globals.enabled || true") result="0";
            else if(cmd=="uci -q get route_policy.vpn.mark") result="0x1000";
            else if(cmd=="iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY") result="-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x1000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP";
            else if(cmd.StartsWith("iptables -w -t mangle -C")) result="";
            else if(cmd=="ip -4 rule show") result="0: from all lookup local\n6000: from all fwmark 0x1000/0xf000 lookup 1001";
            else if(cmd=="ip -4 route show table 1001") result="default dev wgclient1\nblackhole default metric 254";
            else if(cmd=="uci -q get route_policy.vpn.group_id" || cmd=="uci -q get wireguard.peer_11.group_id") result="7";
            else if(cmd=="uci -q get route_policy.vpn.tunnel_id") result="42";
            else if(cmd=="uci -q get route_policy.vpn.via") result="wgclient1";
            else if(cmd=="uci -q get route_policy.vpn.peer_id") result="11";
            else if(cmd.StartsWith("uci -q get network.wgclient1.config")) result="peer_11";
            else if(cmd=="uci -q get wireguard.peer_11.location") result="Germany,Frankfurt";
            else if(cmd.StartsWith("uci -q show route_policy")) result="vpn";
            else if(cmd.StartsWith("grep -Fc '# hotswapper")) result=CompatibilityCatalog.IsPatched(FirmwareHash)?"1":"0";
            else if(cmd==HotswapRuntime.ScanCommand) result=Running?"123 1 daemon":"";
            else if(cmd==HotswapRuntime.PidCommand) result=Running?"123":"";
            else if(cmd.StartsWith("crontab -l")) result=Cron;
            else if(cmd.Contains("&& crontab /root/")) Cron=Uploads["/root/hotswapper/installer/run/cron"];
            else if(cmd.StartsWith("set -e; test ! -L '/root/hotswapper/installer/backups/"))
            {
                var match=Regex.Match(cmd,@"sha256sum '([^']+)'");
                var path=match.Groups[1].Value;
                if(Installed.TryGetValue(path,out var original)) Backups[Hash(original)]=original;
            }
            else if(cmd.Contains(".hotswap-restore"))
            {
                var match=Regex.Match(cmd,@"cp '/root/hotswapper/installer/backups/([^']+)' '([^']+)\.hotswap-restore'");
                if(match.Success) {
                    if(match.Groups[2].Value=="/usr/bin/rtp2.sh") FirmwareHash=match.Groups[1].Value;
                    else Installed[match.Groups[2].Value]=Backups[match.Groups[1].Value];
                }
            }
            else if(cmd.Contains("cp -p '/root/hotswapper/installer/run/"))
            {
                var match=Regex.Match(cmd,@"cp -p '([^']+)' '([^']+)\.hotswap-new'");
                Installed[match.Groups[2].Value]=Uploads[match.Groups[1].Value];
            }
            else if(cmd=="/root/hotswapper/install-gl-guard.sh --install")
            { if(RejectPatch)throw new SafeFailure("The GL reconciliation guard rejected this firmware."); FirmwareHash=CompatibilityCatalog.PatchedHash;RealPatches++; }
            else if(cmd.Contains("/root/hotswapper-supervisor.sh --installer")) Running=true;
            else if(cmd.Contains("kill -TERM ")) Running=false;
            else if(cmd=="/root/hotswapper-main.sh status") result="CURRENT: wgclient1 peer=11 tier=1\nDOWNTIER: none\nUPTIER: none\n";
            else if(cmd.StartsWith("if [ -f /tmp/hotswapper/state"))
                result="current_iface=wgclient1\ncurrent_peer=11\ncurrent_rank=1\ncurrent_tier=1\ndowntier_iface=\ndowntier_peer=\nuptier_iface=\n";
            else if(cmd.StartsWith("if [ -f '"))
            {
                var path=Regex.Match(cmd,@"if \[ -f '([^']+)'").Groups[1].Value;
                result=path=="/usr/bin/rtp2.sh"?FirmwareHash:Installed.TryGetValue(path,out var value)?Hash(value):"";
            }
            else if(cmd.StartsWith("rm -f '"))
                Installed.Remove(Regex.Match(cmd,@"rm -f '([^']+)'").Groups[1].Value);
            else if (!new[] { "test ", "set -e; test ", "sh -n ", "sh /root/hotswapper/installer/run/", "cp /usr/bin/rtp2.sh ",
                "if ip link show wgclient", "grep -Fxq ",
                "uci -q get network.wgclient2.config", "uci -q get network.wgclient3.config", "uci -q show dhcp",
                "if [ -r /tmp/dhcp.leases", "ip -4 neigh show", "ip -o -4 addr show", "if uci -q get dhcp.",
                "/etc/init.d/dnsmasq reload", "wg show ", "rm -rf /root/hotswapper/installer/run" }.Any(cmd.StartsWith))
                throw new InvalidOperationException("Unexpected fixture command: " + cmd);
            return Task.FromResult(result);
        }
    }
}
