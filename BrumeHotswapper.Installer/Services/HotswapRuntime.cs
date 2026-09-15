using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

// Match complete argv shapes, never substrings of a command or a shell -c argument.
public sealed class HotswapRuntime(IRouterTransport router, Func<CancellationToken,Task>? pause = null)
{
    public const string MatchFunction = "owned() { tr '\\000' '\\n' < \"$1\" | awk 'NR==1 && ($0==\"/bin/sh\" || $0==\"/bin/ash\" || $0==\"sh\" || $0==\"ash\") {next} {a[++n]=$0} END {if(n==2 && a[1]==\"/root/vpn-watch.sh\" && (a[2]==\"daemon\" || a[2]==\"run\")) print \"daemon\"; else if(a[1]==\"/root/vpn-watch-supervisor.sh\" && (n==1 || (n==2 && a[2]==\"--installer\"))) print \"supervisor\"}'; }";
    public const string ScanCommand = MatchFunction + "; for f in /proc/[0-9]*/cmdline; do [ -r \"$f\" ] || continue; kind=$(owned \"$f\"); [ -n \"$kind\" ] || continue; pid=${f#/proc/}; pid=${pid%/cmdline}; parent=$(awk '/^PPid:/ {print $2}' /proc/$pid/status 2>/dev/null); printf '%s %s %s\\n' \"$pid\" \"$parent\" \"$kind\"; done";
    public const string PidCommand = "if [ -r /tmp/vpn-watch/lock/pid ]; then cat /tmp/vpn-watch/lock/pid; fi";
    public sealed record Process(string Pid,string Parent,string Kind);
    public static IReadOnlyList<Process> Roots(string snapshot)
    {
        var all = snapshot.Split('\n').Select(l=>Regex.Match(l.Trim(),@"\A([0-9]+) ([0-9]+) (daemon|supervisor)\z"))
            .Where(m=>m.Success).Select(m=>new Process(m.Groups[1].Value,m.Groups[2].Value,m.Groups[3].Value)).ToArray();
        return all.Where(p=>!all.Any(parent=>parent.Pid==p.Parent&&parent.Kind==p.Kind)).ToArray();
    }
    public async Task<IReadOnlyList<Process>> ReadAsync(CancellationToken ct) => Roots(await router.ExecuteAsync(ScanCommand,ct));
    private Task Pause(CancellationToken ct) => pause?.Invoke(ct) ?? Task.Delay(500,ct);
    public static string StopCommand(Process process)
    {
        if (!Regex.IsMatch(process.Pid,@"\A[0-9]+\z") || process.Kind is not ("daemon" or "supervisor")) throw new SafeFailure("Invalid owned process identity.");
        return MatchFunction+$"; if [ -r /proc/{process.Pid}/cmdline ] && [ \"$(owned /proc/{process.Pid}/cmdline)\" = {process.Kind} ]; then kill -TERM {process.Pid}; fi";
    }
    public async Task StopAsync(CancellationToken ct)
    {
        int clear=0;
        for(int i=0;i<20;i++) {
            var processes=await ReadAsync(ct);
            if(processes.Count==0) { if(++clear==2) {
                // No owned supervisor remains. Remove only its empty startup mutex, never daemon state.
                await router.ExecuteAsync("test ! -L /tmp/vpn-watch/supervisor-start && { [ ! -d /tmp/vpn-watch/supervisor-start ] || rmdir /tmp/vpn-watch/supervisor-start; }",ct);
                return;
            }} else {
                clear=0;
                foreach(var process in processes.OrderBy(p=>p.Kind=="supervisor"?0:1)) await router.ExecuteAsync(StopCommand(process),ct);
            }
            await Pause(ct);
        }
        throw new SafeFailure("Owned watchdog/supervisor processes did not stop within 10 seconds; no unrelated process or force-kill was used.");
    }
    public async Task WaitForOneAsync(CancellationToken ct)
    {
        string previous="";
        for(int i=0;i<20;i++) {
            var roots=await ReadAsync(ct);
            var daemons=roots.Where(p=>p.Kind=="daemon").ToArray();
            var owner=(await router.ExecuteAsync(PidCommand,ct)).Trim();
            if(daemons.Length==1 && daemons[0].Pid==owner) {
                if(previous==owner)return;
                previous=owner;
            } else previous="";
            await Pause(ct);
        }
        throw new SafeFailure("Watchdog did not settle to one lock-owning process within 10 seconds.");
    }
}
