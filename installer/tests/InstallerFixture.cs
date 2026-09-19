using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
internal static class InstallerFixture
{
    internal static InstallerConfiguration Config(string hash = CompatibilityCatalog.StockHash)
    {
        var peers = new[] {new VpnConnection("11","VPN connection","Germany,Frankfurt")};
        var tiers = new[] { new TierColumn("Unassigned",0), new TierColumn("Tier 1",1), new TierColumn("Tier 2",2), new TierColumn("Tier 3",3) };
        tiers[1].Locations.Add(new ExactLocationResolver().Group(peers)[0]);
        return new(new("192.0.2.1","GL.iNet GL-MT5000","glinet,gl-mt5000","4.9.0",hash),new("42","7",peers,"vpn"),tiers,false,"",false,[]);
    }
    internal sealed class RouterFixture : IRouterTransport
    {
        private static string NormalizePaths(string value) => Regex.Replace(Regex.Replace(value, @"/run-[a-f0-9]{32}", "/run"), @"\.hotswap-(new|restore)-[a-f0-9]{32}", ".hotswap-$1");
        public Dictionary<string,string> Uploads {get;}=[];
        public Dictionary<string,string> Installed {get;}=[];
        public string FirmwareHash=CompatibilityCatalog.StockHash;
        public Dictionary<string,string> FirmwareHashes = FirmwareTargets.All.Where(t => t.Id != "rtp").ToDictionary(t => t.Path,t => t.StockHash);
        private string FirmwareAt(string path) => path == "/usr/bin/rtp2.sh" ? FirmwareHash : FirmwareHashes[path];
        public void MarkFirmwarePatched() {
            FirmwareHash=CompatibilityCatalog.PatchedHash;
            foreach (var t in FirmwareTargets.All.Where(t => t.Id != "rtp")) FirmwareHashes[t.Path]=t.PatchedHash;
        }
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
                bool exists = FirmwareTargets.Find(metadata.Path) != null || Installed.ContainsKey(metadata.Path);
                result = metadata.Field switch {
                    "symlink" => "0", "exists" => exists ? "1" : "0", "regular" or "readable" => "1",
                    "listing" => (FirmwareTargets.Find(metadata.Path) != null ? "-rwxr-xr-x" : metadata.Path.EndsWith(".sh") ? "-rwx------" : "-rw-------") + " 1 0 0 123 Jan 1 00:00 " + metadata.Path,
                    "size" => "123", "sha256" => FirmwareTargets.Find(metadata.Path) != null ? FirmwareAt(metadata.Path) : Hash(Installed[metadata.Path]), _ => ""
                };
            }
            else if(cmd=="ubus call system board") result="{\"model\":\"GL.iNet GL-MT5000\",\"board_name\":\"glinet,gl-mt5000\"}";
            else if (FirmwareTargets.All.FirstOrDefault(t => cmd == $"sha256sum {t.Path} | awk '{{print $1}}'") is { } firmware) result=FirmwareAt(firmware.Path);
            else if(cmd.StartsWith("sha256sum /root/hotswapper/installer/run/rtp2.preview")) result=CompatibilityCatalog.PatchedHash;
            else if(cmd is "uci -q get route_policy.vpn.killswitch || true" or "uci -q get route_policy.vpn.enabled || true") result="1";
            else if(cmd=="uci -q get route_policy.vpn.via_type || true") result="wireguard";
            else if(cmd=="uci -q get route_policy.global.instance_on || true") result="1";
            else if(cmd=="uci -q get route_policy.gl_process_vpn || true") result="rule_process";
            else if(cmd=="uci -q get route_policy.gl_process_vpn.via || true") result="wgclient1";
            else if(cmd=="uci -q get route_policy.gl_process_vpn.group_id || true") result="";
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
                    else if(FirmwareTargets.Find(match.Groups[2].Value) != null) FirmwareHashes[match.Groups[2].Value]=match.Groups[1].Value;
                    else Installed[match.Groups[2].Value]=Backups[match.Groups[1].Value];
                }
            }
            else if(cmd.Contains("cp -p '/root/hotswapper/installer/run/"))
            {
                var match=Regex.Match(cmd,@"cp -p '([^']+)' '([^']+)\.hotswap-new'");
                Installed[match.Groups[2].Value]=Uploads[match.Groups[1].Value];
            }
            else if(cmd=="/root/hotswapper/install-gl-guard.sh --install")
            { if(RejectPatch)throw new System.IO.IOException("synthetic-private-router-output"); MarkFirmwarePatched();RealPatches++; }
            else if(cmd.Contains("/root/hotswapper-supervisor.sh --installer")) Running=true;
            else if(cmd.Contains("kill -TERM ")) Running=false;
            else if(cmd=="/root/hotswapper-main.sh status") result="CURRENT: wgclient1 peer=11 tier=1\nDOWNTIER: none\nUPTIER: none\n";
            else if(cmd.StartsWith("if [ -f /tmp/hotswapper/state"))
                result="current_iface=wgclient1\ncurrent_peer=11\ncurrent_rank=1\ncurrent_tier=1\ndowntier_iface=\ndowntier_peer=\nuptier_iface=\n";
            else if(cmd.StartsWith("if [ -f '"))
            {
                var path=Regex.Match(cmd,@"if \[ -f '([^']+)'").Groups[1].Value;
                result=FirmwareTargets.Find(path)!=null?FirmwareAt(path):Installed.TryGetValue(path,out var value)?Hash(value):"";
            }
            else if(cmd.StartsWith("rm -f '"))
                Installed.Remove(Regex.Match(cmd,@"rm -f '([^']+)'").Groups[1].Value);
            else if (!new[] { "/root/hotswapper/gl-coordination.sh owned ", "busybox --list", "command -v iptables-restore", "/root/hotswapper/install-gl-guard.sh --verify", "test ", "set -e; test ", "sh -n ", "sh /root/hotswapper/installer/run/", "cp /usr/bin/rtp2.sh ",
                "if ip link show wgclient", "grep -Fxq ",
                "uci -q get network.wgclient2.config", "uci -q get network.wgclient3.config", "uci -q show dhcp",
                "if [ -r /tmp/dhcp.leases", "ip -4 neigh show", "ip -o -4 addr show", "if uci -q get dhcp.",
                "/etc/init.d/dnsmasq reload", "wg show ", "rm -rf /root/hotswapper/installer/run" }.Any(cmd.StartsWith))
                throw new InvalidOperationException("Unexpected fixture command: " + cmd);
            return Task.FromResult(result);
        }
    }
}
