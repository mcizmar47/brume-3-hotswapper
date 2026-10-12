using System.IO;
using Renci.SshNet;
using BrumeHotswapper.Installer.Core;

namespace BrumeHotswapper.Installer.Services;

// The session lock excludes other installers. The operation lock keeps a
// command alive across a lost SSH lock channel until its router work finishes.
public sealed class SshInstallerLock : IAsyncDisposable
{
    public const string Command = "umask 077; test ! -L /tmp/hotswapper && mkdir -p /tmp/hotswapper && test ! -L /tmp/hotswapper/installer.lock && test ! -L /tmp/hotswapper/installer.ops && test ! -L /tmp/hotswapper/installer.owner || exit 1; exec 5>/tmp/hotswapper/installer.lock; busybox flock -n 5 || exit 1; exec 6>/tmp/hotswapper/installer.ops; busybox flock 6 || exit 1; printf '__TOKEN__\\n' > /tmp/hotswapper/installer.owner; busybox flock -u 6; exec 6>&-; printf 'LOCKED\\n'; read -r release; exec 6>/tmp/hotswapper/installer.ops; busybox flock 6 || exit 1; if [ \"$(cat /tmp/hotswapper/installer.owner 2>/dev/null)\" = __TOKEN__ ]; then rm -f /tmp/hotswapper/installer.owner; fi";
    public const string OperationPrefix = "exec 6>/tmp/hotswapper/installer.ops; busybox flock 6 || exit 1; test \"$(cat /tmp/hotswapper/installer.owner 2>/dev/null)\" = __TOKEN__ || exit 1; ";
    private readonly SshCommand command;
    private readonly Stream input;
    private readonly Task execution;
    public string Token { get; }
    public bool IsDisposed { get; private set; }
    private SshInstallerLock(SshCommand command, Stream input, Task execution, string token)
    { this.command = command; this.input = input; this.execution = execution; Token = token; }

    public string Guard(string script)
    {
        EnsureHeld();
        return OperationPrefix.Replace("__TOKEN__", Token) + script;
    }

    public void EnsureHeld()
    {
        if (IsDisposed || execution.IsCompleted)
            throw new SafeFailure("The live installer lock was lost. No further installer commands will be sent; transaction evidence was retained.");
    }
    public static async Task<SshInstallerLock> AcquireAsync(SshClient ssh, CancellationToken ct)
    {
        string token = Guid.NewGuid().ToString("N");
        var command = ssh.CreateCommand(Command.Replace("__TOKEN__", token));
        command.CommandTimeout = Timeout.InfiniteTimeSpan;
        var execution = command.ExecuteAsync(CancellationToken.None);
        var lease = new SshInstallerLock(command, command.CreateInputStream(), execution, token);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(6));
            using var reader = new StreamReader(command.OutputStream, leaveOpen: true);
            if (await reader.ReadLineAsync(timeout.Token) != "LOCKED")
                throw new SafeFailure("Another installer is active, or the router installer lock could not be acquired.");
            return lease;
        }
        catch
        {
            await lease.DisposeAsync();
            ct.ThrowIfCancellationRequested();
            throw new SafeFailure("Another installer is active, or the router installer lock could not be acquired.");
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (IsDisposed) return;
        IsDisposed = true;
        input.Dispose();
        try { await execution.WaitAsync(TimeSpan.FromSeconds(5)); }
        catch { try { command.CancelAsync(); } catch { /* SSH may already be closed. */ } }
        finally { command.Dispose(); }
    }
}
