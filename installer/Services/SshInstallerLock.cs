using System.IO;
using Renci.SshNet;
using BrumeHotswapper.Installer.Core;

namespace BrumeHotswapper.Installer.Services;

// A dedicated SSH channel holds flock until stdin closes. No PID cleanup or lease timer.
public sealed class SshInstallerLock : IAsyncDisposable
{
    public const string Command = "umask 077; test ! -L /tmp/hotswapper && mkdir -p /tmp/hotswapper && test ! -L /tmp/hotswapper/installer.lock || exit 1; exec 5>/tmp/hotswapper/installer.lock; busybox flock -n 5 || exit 1; printf 'LOCKED\\n'; read -r release";
    private readonly SshCommand command;
    private readonly Stream input;
    private readonly Task execution;
    private SshInstallerLock(SshCommand command, Stream input, Task execution)
    { this.command = command; this.input = input; this.execution = execution; }

    public static async Task<IAsyncDisposable> AcquireAsync(SshClient ssh, CancellationToken ct)
    {
        var command = ssh.CreateCommand(Command);
        command.CommandTimeout = Timeout.InfiniteTimeSpan;
        var execution = command.ExecuteAsync(CancellationToken.None);
        var lease = new SshInstallerLock(command, command.CreateInputStream(), execution);
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
        input.Dispose();
        try { await execution.WaitAsync(TimeSpan.FromSeconds(5)); }
        catch { command.CancelAsync(); }
        finally { command.Dispose(); }
    }
}
