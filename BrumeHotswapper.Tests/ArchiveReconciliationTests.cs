using System.IO;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
using static BrumeHotswapper.Tests.SecondPassTests;
namespace BrumeHotswapper.Tests;

public class ArchiveReconciliationTests
{
    private sealed class Intercept(IRouterTransport inner) : IRouterTransport
    {
        public Func<string, string?>? Read;
        public Action<string>? Before, After;
        public Action<string>? Upload;
        public List<string> Commands = [];
        public async Task<string> ExecuteAsync(string command, CancellationToken ct)
        {
            Commands.Add(command); Before?.Invoke(command);
            var result = Read?.Invoke(command) ?? await inner.ExecuteAsync(command, ct);
            After?.Invoke(command); return result;
        }
        public Task UploadAsync(string path, string content, CancellationToken ct)
        { Upload?.Invoke(path); return inner.UploadAsync(path, content, ct); }
    }
    [Theory]
    [InlineData("1", "", "marking and DROP")]
    public async Task KillSwitchSeparatesIntentFromEnforcement(string enabled, string rules, string message)
    {
        var router = new Intercept(new RouterFixture()) { Read = cmd => cmd switch {
            "uci -q get route_policy.vpn.killswitch || true" => enabled,
            "uci -q get route_policy.vpn.enabled || true" => "1",
            "uci -q get glipv6.globals.enabled || true" => "0",
            "uci -q get route_policy.vpn.mark" => "0x1000",
            "iptables -w -t mangle -S TUNNEL42_ROUTE_POLICY" => rules,
            _ => null
        }};
        var error = await Assert.ThrowsAsync<SafeFailure>(() => new KillSwitchVerifier().VerifyAsync(router, "vpn", default));
        Assert.Contains(message, error.Message);
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
        var installer = new RouterInstaller(router, new VerifiedKillSwitch());
        var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.PlanAsync(Config(), default));
        Assert.Contains("another VPN policy", error.Message);
    }
    [Theory]
    [InlineData(2, false)] // sticky Tier 2, unavailable next pool
    [InlineData(2, true)]  // sticky Tier 2 with PRECOOKED
    [InlineData(3, false)] // Tier 3: recovery slot can be probing a better tier
    [InlineData(1, false)] // Tier 1 with backoff
    public void HealthyActiveDoesNotRequireAvailableStandby(int tier, bool standby)
    {
        var c = Config();
        var peers = new[] { new VpnConnection("11", "", "A,One"), new VpnConnection("12", "", "B,Two"), new VpnConnection("13", "", "C,Three"), new VpnConnection("14", "", "B,Two") };
        c = c with { Profile = c.Profile with { Connections = peers } };
        foreach (var t in c.Tiers) t.Locations.Clear();
        var resolver = new ExactLocationResolver();
        c.Tiers[1].Locations.Add(resolver.Group([peers[0]])[0]);
        c.Tiers[2].Locations.Add(resolver.Group([peers[1], peers[3]])[0]);
        c.Tiers[3].Locations.Add(resolver.Group([peers[2]])[0]);
        var peer = tier == 2 ? "14" : tier == 1 ? "11" : "13";
        string state = $"active_iface=wgclient2\nactive_peer={peer}\nactive_rank={tier}\nactive_tier={tier}\nrecovery_iface=wgclient1\n" +
            (standby ? "standby_iface=wgclient3\nstandby_peer=13\nstandby_rank=3\nstandby_tier=3\n" : "standby_iface=\nstandby_peer=\nstandby_rank=0\nstandby_tier=0\n");
        Assert.True(RuntimeValidation.IsHealthy(state, c));
        Assert.False(RuntimeValidation.IsHealthy(state.Replace("recovery_iface=wgclient1", "recovery_iface=wgclient2"), c));
        if (standby) Assert.False(RuntimeValidation.IsHealthy(state.Replace("standby_rank=3", "standby_rank=1"), c));
    }
    [Theory]
    [InlineData("upload")]
    [InlineData("file-before")]
    [InlineData("file-after")]
    [InlineData("cron")]
    public async Task FailureBeforeRuntimeRollsBackOwnedChanges(string boundary)
    {
        var fake = new RouterFixture(); var router = new Intercept(fake);
        var installer = new RouterInstaller(router, new VerifiedKillSwitch());
        var plan = await installer.PlanAsync(Config(), default);
        bool fired = false;
        void Fail(string cmd, string expected)
        { if (!fired && cmd.Contains(expected)) { fired = true; throw new OperationCanceledException("synthetic-secret-must-not-escape"); } }
        if (boundary == "upload") router.Upload = p => { if (p.EndsWith("/vpn-watch.conf")) fake.Uploads[p] = "partial upload"; Fail(p, "/vpn-watch.conf"); };
        if (boundary == "file-before") router.Before = p => Fail(p, "cp -p");
        if (boundary == "file-after") router.After = p => Fail(p, "cp -p");
        if (boundary == "cron") router.Before = p => Fail(p, "&& crontab");
        var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.InstallAsync(plan, new Progress<string>(), default));
        Assert.True(fired); Assert.Contains("rolled back", error.Message);
        Assert.DoesNotContain("synthetic-secret", error.Message); Assert.Empty(fake.Installed);
    }
    [Fact] public async Task StartedRuntimeFailureRestoresFilesWhenPolicyUnchanged()
    {
        var fake = new RouterFixture(); var router = new Intercept(fake);
        var installer = new RouterInstaller(router, new VerifiedKillSwitch());
        var plan = await installer.PlanAsync(Config(), default);
        router.After = cmd => { if (cmd.StartsWith("rm -f /tmp/vpn-watch/state")) throw new IOException("synthetic-secret"); };
        var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.InstallAsync(plan, new Progress<string>(), default));
        Assert.Contains("rolled back", error.Message); Assert.Empty(fake.Installed);
        Assert.Contains(router.Commands, c => c.Contains("rm -rf /root/.hotswap-installer/run-"));
        Assert.False(fake.Running); Assert.DoesNotContain("synthetic-secret", error.Message);
    }
    [Fact] public async Task CleanupFailureDoesNotUndoValidatedInstallation()
    {
        var fake = new RouterFixture(); var router = new Intercept(fake);
        var installer = new RouterInstaller(router, new VerifiedKillSwitch());
        var plan = await installer.PlanAsync(Config(), default);
        router.Before = cmd => { if (cmd.Contains("rm -rf /root/.hotswap-installer/run-")) throw new IOException(); };
        var result = await installer.InstallAsync(plan, new Progress<string>(), default);
        Assert.True(result.Success); Assert.True(fake.Running); Assert.Equal(7, fake.Installed.Count);
    }
    [Fact] public async Task InstallRetainsUnrelatedCronEditMadeAfterReview()
    {
        var fake = new RouterFixture(); var router = new Intercept(fake);
        var installer = new RouterInstaller(router, new VerifiedKillSwitch());
        var plan = await installer.PlanAsync(Config(), default);
        router.After = cmd => { if (cmd.Contains("mkdir -p /root/.hotswap-installer/backups")) fake.Cron += "22 2 * * * /root/new-user-job\n"; };
        await installer.InstallAsync(plan, new Progress<string>(), default);
        Assert.Contains("/root/new-user-job", fake.Cron);
    }
    [Fact] public void MalformedLanMetadataCannotBeUsedAsIpv4()
    {
        Assert.False(new LanNetwork("::1", "255.255.255.0", 100, 150).ContainsHost("192.0.2.20"));
        Assert.False(new LanNetwork("192.0.2.1", "255.0.255.0", 100, 150).ContainsHost("192.0.2.20"));
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
        await new RouterInstaller(router, new VerifiedKillSwitch()).PlanAsync(Config(), default);
    }
    [Theory]
    [InlineData("uci -P")]
    [InlineData("/etc/init.d/dnsmasq reload")]
    public async Task DhcpBoundaryFailureRetainsReservationsAndCleansTemporaryFiles(string boundary)
    {
        var fake = new RouterFixture();
        var router = new Intercept(fake) { Read = cmd => cmd switch {
            "uci -q get network.lan.ipaddr" => "192.0.2.1",
            "uci -q get network.lan.netmask" => "255.255.255.0",
            "uci -q get dhcp.lan.start" => "100",
            "uci -q get dhcp.lan.limit" => "150",
            _ => null
        }};
        var c = Config() with { Guards = [new("PC", "192.0.2.20", "02:00:00:00:00:20")] };
        var installer = new RouterInstaller(router, new VerifiedKillSwitch());
        var plan = await installer.PlanAsync(c, default);
        router.After = cmd => { if (cmd.Contains(boundary)) throw new IOException(); };
        var error = await Assert.ThrowsAsync<SafeFailure>(() => installer.InstallAsync(plan, new Progress<string>(), default));
        Assert.Contains("retained for reuse", error.Message);
        Assert.DoesNotContain(router.Commands, cmd => cmd.Contains("uci delete"));
        Assert.Contains(router.Commands,cmd=>cmd.Contains("rm -rf /root/.hotswap-installer/run-"));
        Assert.DoesNotContain(fake.Uploads.Keys,k=>k.EndsWith("journal.json"));
    }
    [Fact] public void HistoricalPatchHashRetainsVariantIdentity()
    {
        Assert.Equal(Compatibility.HistoricalGuardKnownCompatible, CompatibilityCatalog.Classify("5b1a898d8a4943d256f0674c0050519f1ec1353327f7de0778e1c760d3e57704"));
    }
}
