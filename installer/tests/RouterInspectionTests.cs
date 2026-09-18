using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using static BrumeHotswapper.Tests.InstallerFixture;
namespace BrumeHotswapper.Tests;
public class RouterInspectionTests
{
    [Fact] public async Task MultipleListsRequireExplicitSelectionAndUseAllowlistedFields()
    {
        var router = new DiscoveryRouter();
        var profiles = await new VpnDiscovery(router).DiscoverAsync(CancellationToken.None);
        Assert.Equal(2, profiles.Count); Assert.Null(VpnDiscovery.AutoSelect(profiles));
        Assert.Equal("902",profiles[1].TunnelId); Assert.Equal("72",profiles[1].GroupId);
        Assert.All(router.Commands, c => {
            Assert.DoesNotContain("uci -q show wireguard",c);
            Assert.DoesNotContain("private_key",c); Assert.DoesNotContain(".name",c);
        });
        Assert.Same(profiles[0],VpnDiscovery.AutoSelect([profiles[0]]));
    }
    private class DiscoveryRouter : IRouterTransport
    {
        public List<string> Commands=[];
        public Task UploadAsync(string p,string c,CancellationToken ct)=>throw new Exception("Discovery must not write");
        public Task<string> ExecuteAsync(string cmd,CancellationToken ct)
        {
            Commands.Add(cmd);
            return Task.FromResult(cmd switch {
                var c when c.StartsWith("uci -q show route_policy")=>"gl_process 800\ngl_process_vpn 801\npolicyA 901\npolicyB 902\n",
                "uci -q get route_policy.gl_process.group_id || true"=>"",
                "uci -q get route_policy.gl_process_vpn.group_id || true"=>"",
                "uci -q get route_policy.policyA.group_id || true"=>"71",
                "uci -q get route_policy.policyB.group_id || true"=>"72",
                var c when c.Contains("profile901")=>"peer_501\n",
                var c when c.Contains("profile902")=>"peer_502\n",
                "uci -q get wireguard.peer_501.group_id || true"=>"71",
                "uci -q get wireguard.peer_502.group_id || true"=>"72",
                "uci -q get wireguard.peer_501.location || true"=>"Fictionland,Example",
                "uci -q get wireguard.peer_502.location || true"=>"Elsewhere,Another City",
                _=>throw new Exception("Unexpected discovery field")
            });
        }
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task ExistingChoiceAndUnrelatedRoutingAreSupported(string setting)
    {
        var router = new Fixture(setting);
        await new KillSwitchVerifier().VerifyAsync(router,"vpn",default);
        Assert.DoesNotContain(router.Commands,c=>c.Contains("table 9910") || c.Contains("table 16800"));
        if(setting=="0") Assert.DoesNotContain(router.Commands,c=>c.StartsWith("iptables"));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task WrongActiveRouteBlocksInBothModes(string setting)
    {
        var router=new Fixture(setting){Routes="default dev wgclient3\nblackhole default metric 254"};
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task WrongSelectedTableBlocksInBothModes(string setting)
    {
        var router=new Fixture(setting){Table="1003"};
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(router,"vpn",default));
    }
    [Fact] public async Task EnabledRequiresEnforcement()
    {
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(new Fixture("1"){Firewall=""},"vpn",default));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task SlotConflictsBlockBothChoices(string setting)
    {
        var router=new TransactionFixture(new InstallerFixture.RouterFixture(),setting){Conflict=true};
        await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInstaller(router,new KillSwitchVerifier()).PlanAsync(InstallerFixture.Config(),default));
    }
    [Theory][InlineData("0")][InlineData("1")]
    public async Task Ipv6IsAnIndependentProductionBlock(string setting)
    {
        var router=new TransactionFixture(new InstallerFixture.RouterFixture(),setting){Ipv6=true};
        await new KillSwitchVerifier().VerifyAsync(router,"vpn",default);
        var error=await Assert.ThrowsAsync<SafeFailure>(()=>new RouterInstaller(router,new KillSwitchVerifier()).PlanAsync(InstallerFixture.Config(),default));
        Assert.Contains("IPv6",error.Message);

    }
    private sealed class TransactionFixture(InstallerFixture.RouterFixture inner,string setting):IRouterTransport
    {
        public bool Conflict,Ipv6;
        public Task UploadAsync(string p,string s,CancellationToken ct)=>inner.UploadAsync(p,s,ct);
        public Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            if(c.Contains("killswitch")) {
                Assert.Equal("uci -q get route_policy.vpn.killswitch || true",c);
                return Task.FromResult(setting);
            }
            if(setting=="0") Assert.False(c.StartsWith("iptables"));
            if(Ipv6&&c=="uci -q get glipv6.globals.enabled || true")return Task.FromResult("1");
            if(Conflict&&c=="uci -q get network.wgclient2.config || true")return Task.FromResult("peer_99");
            if(Conflict&&c=="uci -q get wireguard.peer_99.group_id")return Task.FromResult("99");
            return inner.ExecuteAsync(c,ct);
        }
    }
    [Fact] public async Task DisabledNeedsNoTerminalDropRoute()
    {
        await new KillSwitchVerifier().VerifyAsync(new Fixture("0"){Routes="default dev wgclient2"},"vpn",default);
    }
    [Theory][InlineData("")][InlineData("2")]
    public async Task UnknownChoiceIsNotSilentlyDefaulted(string setting)
    {
        await Assert.ThrowsAsync<SafeFailure>(()=>new KillSwitchVerifier().VerifyAsync(new Fixture(setting),"vpn",default));
    }
    private sealed class Fixture(string setting):IRouterTransport
    {
        public string Table="1002",Routes="default dev wgclient2\nblackhole default metric 254";
        public string Firewall="-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0x2000/0xf000\n-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000 -j DROP";
        public List<string> Commands=[];
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception("No writes");
        public Task<string> ExecuteAsync(string c,CancellationToken ct)
        {
            Commands.Add(c);
            return Task.FromResult(c switch {
                "uci -q get route_policy.vpn.killswitch || true"=>setting,
                "uci -q get route_policy.vpn.enabled || true"=>"1",
                "uci -q get glipv6.globals.enabled || true"=>"0",
                "uci -q get route_policy.vpn.tunnel_id"=>"42",
                "uci -q get route_policy.vpn.mark"=>"0x2000",
                "uci -q get route_policy.vpn.via"=>"wgclient2",
                "ip -4 rule show"=>"1: from all iif lo lookup 16800\n800: from all lookup 9910 suppress_prefixlength 0\n6000: from all fwmark 0x2000/0xf000 lookup "+Table,
                "ip -4 route show table 1002" or "ip -4 route show table 1003"=>Routes,
                "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY" when setting=="1"=>Firewall,
                var x when x.StartsWith("iptables -w -t mangle -C") && setting=="1"=>"",
                _=>throw new SafeFailure("Unexpected read or mutation")
            });
        }
    }
    [Fact] public void DropMustMatchTheMarkingScopeAndOrder()
    {
        const string prefix = "-A TUNNEL42_ROUTE_POLICY -m mark --mark 0x0/0xf000";
        const string mark = prefix + " -m set ! --match-set dst_net42 dst -j MARK --set-xmark 0x1000/0xf000";
        const string drop = prefix + " -m set ! --match-set dst_net42 dst -j DROP";
        Assert.True(KillSwitchVerifier.HasPolicyRules(mark + "\n" + drop, "TUNNEL42_ROUTE_POLICY", "0x1000"));
        Assert.False(KillSwitchVerifier.HasPolicyRules(mark + "\n" + drop.Replace("dst_net42", "dst_net43"), "TUNNEL42_ROUTE_POLICY", "0x1000"));
        Assert.False(KillSwitchVerifier.HasPolicyRules(drop + "\n" + mark, "TUNNEL42_ROUTE_POLICY", "0x1000"));
    }
    [Fact] public async Task EmptySlotReferencedByAnotherPolicyIsRefused()
    {
        var router = new Intercept(new RouterFixture()) { Read = cmd => cmd.Contains(".via='wgclient2'") ? "other" : null };
        var installer = new RouterInstaller(router, new KillSwitchVerifier());
        var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.PlanAsync(Config(), default));
        Assert.Contains("another VPN policy", error.Message);
    }
    [Fact] public async Task AnonymousPolicyAndFirmwareProcessReferenceAreSupported()
    {
        var fake = new RouterFixture();
        var router = new Intercept(fake) { Read = cmd => cmd switch {
            var x when x.StartsWith("uci -q show route_policy") && x.Contains(".tunnel_id=") => "gl_process 40\ngl_process_vpn 41\n@rule[0] 42\n",
            "uci -q get route_policy.gl_process.group_id || true" => "",
            "uci -q get route_policy.gl_process_vpn.group_id || true" => "",
            "uci -q get route_policy.'@rule[0]'.group_id || true" => "7",
            var x when x.Contains("sed -n 's/^7_") => "peer_11\n",
            "uci -q get wireguard.peer_11.group_id || true" => "7",
            "uci -q get wireguard.peer_11.location || true" => "A,One",
            _ => null
        }};
        var profile = Assert.Single(await new VpnDiscovery(router).DiscoverAsync(default));
        Assert.Equal("@rule[0]", profile.PolicySection);
        Assert.Contains(router.Commands, cmd => cmd.Contains("sed -n 's/^7_"));
        Assert.Equal("'@rule[0]'", RouterInspection.Identifier(profile.PolicySection));
        Assert.Throws<SafeFailure>(() => RouterInspection.Identifier("@rule[0];id"));
        router.Read = cmd => cmd switch {
            var x when x.Contains(".via='wgclient1'") => "vpn\ngl_process_vpn\n",
            "uci -q get route_policy.gl_process_vpn" => "rule_process",
            "uci -q get route_policy.gl_process_vpn.group_id || true" => "",
            _ => null
        };
        await new RouterInstaller(router, new KillSwitchVerifier()).PlanAsync(Config(), default);
    }
    private sealed class Intercept(IRouterTransport inner) : IRouterTransport
    {
        public Func<string, string?>? Read;
        public List<string> Commands = [];
        public async Task<string> ExecuteAsync(string command, CancellationToken ct)
        {
            Commands.Add(command);
            var result = Read?.Invoke(command) ?? await inner.ExecuteAsync(command, ct);
            return result;
        }
        public Task UploadAsync(string path, string content, CancellationToken ct)
        { return inner.UploadAsync(path, content, ct); }
    }
    [Fact] public async Task BusyBoxFieldsAreIndependentAndTrimmed()
    {
        var fields = await FileMetadata.ReadAsync(new MetadataFixture(), "/root/hotswapper-main.sh", default);
        Assert.Equal("0", fields["uid"]); Assert.Equal("755", fields["mode"]); Assert.Equal("81001", fields["size"]);
        Assert.True(FileMetadata.Validate("/root/hotswapper-main.sh", fields).Exists);
    }
    private sealed class MetadataFixture : IRouterTransport {
        public Task UploadAsync(string p,string s,CancellationToken ct)=>throw new Exception();
        public Task<string> ExecuteAsync(string c,CancellationToken ct)=>Task.FromResult(c switch {
            var x when x.StartsWith("if [ -L") => "0\r\n", var x when x.StartsWith("if [") => "1\n",
            var x when x.StartsWith("LC_ALL=C ls -ldn ") => "-rwxr-xr-x    1 0 0 55880 Jan 1 00:00 /root/hotswapper-main.sh\n",
            var x when x.StartsWith("wc -c") => "   81001\n",
            var x when x.StartsWith("sha256sum") => new string('a',64)+"\n", _=>throw new Exception() });
    }
    [Theory]
    [InlineData("")]
    [InlineData("-rwxr-xr-x 1 root root 55880 ...")]
    public void MalformedListingBlocks(string listing)=>Assert.Throws<SafeFailure>(()=>FileMetadata.ParseListing(listing));
    [Theory]
    [InlineData("-rwxr-xr-x",0,0,"PASS")][InlineData("-rwx------",0,0,"PASS")]
    [InlineData("-rwxrwxr-x",0,0,"BLOCK")]
    [InlineData("-rwsr-xr-x",0,0,"BLOCK")]
    [InlineData("-rwxr-xr-x",10,0,"BLOCK")]
    [InlineData("lrwxrwxrwx",0,0,"BLOCK")]
    public void InstallerAppliesMetadataSafetyPolicy(string symbolic,uint uid,uint gid,string expected)
    {
        var parsed=FileMetadata.ParseListing($"{symbolic} 1 {uid} {gid} 55880 ... file with spaces");
        var fields=new Dictionary<string,string>{{"exists","1"},{"regular","1"},{"symlink",symbolic[0]=='l'?"1":"0"},{"readable","1"},{"type",parsed.Type.ToString()},{"mode",parsed.Mode},{"uid",parsed.Uid.ToString()},{"gid",parsed.Gid.ToString()},{"size","55880"},{"sha256",new string('a',64)}};
        if(expected=="BLOCK") Assert.Throws<SafeFailure>(()=>FileMetadata.Validate("/root/hotswapper-main.sh",fields));
        else FileMetadata.Validate("/root/hotswapper-main.sh",fields);
    }
}
