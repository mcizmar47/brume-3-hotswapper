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
        const string good="active_iface=wgclient1\nactive_peer=11\nactive_rank=1\nactive_tier=1\nstandby_iface=\nstandby_peer=\nrecovery_iface=wgclient2\n";
        Assert.True(RuntimeValidation.IsHealthy(good,c));
        Assert.False(RuntimeValidation.IsHealthy(good.Replace("active_peer=11","active_peer=999"),c));
        Assert.False(RuntimeValidation.IsHealthy(good.Replace("recovery_iface=wgclient2","recovery_iface=wgclient1"),c));
    }
    [Fact] public async Task RealTransactionCanCompleteWithVerifiedPreconditions()
    {
        var fake=new RouterFixture(); var installer=new RouterInstaller(fake,new VerifiedKillSwitch());
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
        var plan=await installer.PlanAsync(Config(),CancellationToken.None);
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
        var c=Config() with {Notifications=true,NtfyUrl="https://example.invalid/synthetic-test-topic"};
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
        public Dictionary<string,string> Uploads {get;}=[];
        public Dictionary<string,string> Installed {get;}=[];
        public string FirmwareHash=CompatibilityCatalog.StockHash;
        public string Cron="";
        public bool Running,RejectPatch;
        public int RealPatches;
        private static string Hash(string s)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        public Task UploadAsync(string path,string content,CancellationToken ct) {ct.ThrowIfCancellationRequested();Uploads[path]=content;return Task.CompletedTask;}
        public Task<string> ExecuteAsync(string cmd,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            string result="";
            if(cmd=="ubus call system board") result="{\"model\":\"GL.iNet GL-MT5000\",\"board_name\":\"glinet,gl-mt5000\"}";
            else if(cmd.StartsWith("sha256sum /usr/bin/rtp2.sh")) result=FirmwareHash;
            else if(cmd.StartsWith("sha256sum /root/.hotswap-installer/transaction/rtp2.preview")) result=CompatibilityCatalog.PatchedHash;
            else if(cmd=="uci -q get route_policy.vpn.group_id" || cmd=="uci -q get wireguard.peer_11.group_id") result="7";
            else if(cmd=="uci -q get route_policy.vpn.tunnel_id") result="42";
            else if(cmd=="uci -q get route_policy.vpn.via") result="wgclient1";
            else if(cmd=="uci -q get route_policy.vpn.peer_id") result="11";
            else if(cmd.StartsWith("uci -q get network.wgclient1.config")) result="peer_11";
            else if(cmd=="uci -q get wireguard.peer_11.location") result="Germany,Frankfurt";
            else if(cmd.StartsWith("uci -q show route_policy")) result="vpn";
            else if(cmd.StartsWith("grep -Fc '# vpn-watch")) result=FirmwareHash==CompatibilityCatalog.PatchedHash?"1":"0";
            else if(cmd.StartsWith("test ! -L '/") && cmd.Contains("stat -c %a"))
            {
                var path=Regex.Match(cmd,@"test ! -L '([^']+)'").Groups[1].Value;
                result=path=="/usr/bin/rtp2.sh"?FirmwareHash+"\n755":Installed.TryGetValue(path,out var existing)?Hash(existing)+"\n"+(path.EndsWith(".sh")?"700":"600"):"absent";
            }
            else if(cmd.StartsWith("for f in /proc/")) result=Running?"123":"";
            else if(cmd=="stat -c %a '/usr/bin/rtp2.sh'") result="755";
            else if(cmd.StartsWith("crontab -l")) result=Cron;
            else if(cmd.Contains("&& crontab /root/")) Cron=Uploads["/root/.hotswap-installer/transaction/cron"];
            else if(cmd.Contains("cp -p '/root/.hotswap-installer/transaction/"))
            {
                var match=Regex.Match(cmd,@"cp -p '([^']+)' '([^']+)\.hotswap-new'");
                Installed[match.Groups[2].Value]=Uploads[match.Groups[1].Value];
            }
            else if(cmd=="/root/install-vpn-watch-gl-guard.sh --install")
            { if(RejectPatch)throw new SafeFailure("The GL reconciliation guard rejected this firmware."); FirmwareHash=CompatibilityCatalog.PatchedHash;RealPatches++; }
            else if(cmd.Contains("/root/vpn-watch-supervisor.sh --installer")) Running=true;
            else if(cmd.Contains("kill -TERM ")) Running=false;
            else if(cmd.StartsWith("if [ -f /tmp/vpn-watch/state"))
                result="active_iface=wgclient1\nactive_peer=11\nactive_rank=1\nactive_tier=1\nstandby_iface=\nstandby_peer=\nrecovery_iface=wgclient2\n";
            else if(cmd.StartsWith("if [ -f '"))
            {
                var path=Regex.Match(cmd,@"if \[ -f '([^']+)'").Groups[1].Value;
                result=path=="/usr/bin/rtp2.sh"?FirmwareHash:Installed.TryGetValue(path,out var value)?Hash(value):"";
            }
            else if(cmd.StartsWith("rm -f '"))
                Installed.Remove(Regex.Match(cmd,@"rm -f '([^']+)'").Groups[1].Value);
            else if (!new[] { "test ", "set -e; test ", "sh -n ", "sh /root/.hotswap-installer/transaction/", "cp /usr/bin/rtp2.sh ",
                "if [ -e /root/.hotswap-installer/transaction", "if ip link show wgclient", "grep -Fxq ",
                "uci -q get network.wgclient2.config", "uci -q get network.wgclient3.config", "uci -q show dhcp",
                "if [ -r /tmp/dhcp.leases", "ip -4 neigh show", "ip -o -4 addr show", "if uci -q get dhcp.",
                "/etc/init.d/dnsmasq reload", "wg show ", "rm -rf /root/.hotswap-installer/transaction" }.Any(cmd.StartsWith))
                throw new InvalidOperationException("Unexpected fixture command: " + cmd);
            return Task.FromResult(result);
        }
    }
}
