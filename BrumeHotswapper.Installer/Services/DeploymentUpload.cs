using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

public enum UploadKind { Sftp, SshStream }
public interface IUploadChannel
{
    Task<bool> SftpAvailableAsync(CancellationToken ct);
    Task<string> StreamAsync(string command, ReadOnlyMemory<byte> bytes, CancellationToken ct);
    Task SftpAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken ct);
    Task<string> CommandAsync(string command, CancellationToken ct);
}
public sealed class DeploymentUpload(IUploadChannel channel)
{
    public const string Stage = "/root/.hotswap-installer/transaction";
    public const int MaximumBytes = 2 * 1024 * 1024;
    private UploadKind? selected;
    public static string Hash(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    public static void ValidatePath(string path)
    {
        if (!Regex.IsMatch(path, @"^/root/\.hotswap-installer/transaction/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\z") || path.EndsWith("/owner"))
            throw new SafeFailure("Upload destination is outside installer staging or has unsupported characters.");
    }
    public async Task<UploadKind> ProbeAsync(CancellationToken ct)
    {
        // No remote files: stdin is hashed, allowing a real channel/EOF/binary capability test.
        byte[] probe = Enumerable.Range(0, 65536).Select(x => (byte)x).ToArray();
        bool streamWorks;
        try { streamWorks = (await channel.StreamAsync("sha256sum | awk '{print $1}'", probe, ct)).Trim() == Hash(probe); }
        catch (OperationCanceledException) { throw; }
        catch { streamWorks = false; }
        if (streamWorks) { selected = UploadKind.SshStream; return selected.Value; }
        bool sftpWorks;
        try { sftpWorks = await channel.SftpAvailableAsync(ct); }
        catch (OperationCanceledException) { throw; }
        catch { sftpWorks = false; }
        // Streaming is preferred: supported on the tested router without a subsystem dependency.
        selected = sftpWorks ? UploadKind.Sftp : null;
        return selected ?? throw new SafeFailure("No verified deployment upload transport is available.");
    }
    public async Task UploadAsync(string path, ReadOnlyMemory<byte> bytes, CancellationToken ct)
    {
        ValidatePath(path);
        if (bytes.Length > MaximumBytes) throw new SafeFailure("Upload exceeds deployment limit.");
        ct.ThrowIfCancellationRequested();
        var kind = selected ?? await ProbeAsync(ct);
        string owner = (await channel.CommandAsync($"cat {Stage}/owner", ct)).Trim();
        if (!Regex.IsMatch(owner, "^[a-f0-9]{32}$")) throw new SafeFailure("Upload requires an owned transaction journal.");
        string temporary = Stage + "/.upload-" + Guid.NewGuid().ToString("N");
        string guard = $"test ! -L /root/.hotswap-installer && test ! -L {Stage} && test -d {Stage} && test ! -L {Stage}/owner && test \"$(cat {Stage}/owner)\" = '{owner}' && test \"$(id -u)\" = 0 && {FileMetadata.MatchesCommand(Stage, "700", 'd')}";
        string cleanup = $"if test ! -L /root/.hotswap-installer && test ! -L {Stage} && test \"$(cat {Stage}/owner)\" = '{owner}'; then rm -f '{temporary}'; fi";
        try
        {
            string prepare = guard + $" || exit 1; test ! -L '{path}' || exit 1; umask 077; set -C; ";
            // set -e prevents failed guard checks from falling through to creation.
            if (kind == UploadKind.SshStream)
                await channel.StreamAsync("set -e; " + prepare + $"cat > '{temporary}'", bytes, ct);
            else {
                await channel.CommandAsync("set -e; " + prepare + $": > '{temporary}'", ct);
                await channel.SftpAsync(temporary, bytes, ct);
            }
            string metadata = await channel.CommandAsync(guard + $" && test -f '{temporary}' && test ! -L '{temporary}' && {FileMetadata.MatchesCommand(temporary, "600")} && wc -c < '{temporary}' && sha256sum '{temporary}' | awk '{{print $1}}'", ct);
            var fields = metadata.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 2 || !long.TryParse(fields[0], out long size) || size != bytes.Length || fields[1] != Hash(bytes.Span))
                throw new SafeFailure("Staged upload length or SHA-256 verification failed.");
            // Repeat integrity and ownership tests in the compare-before-publish command.
            await channel.CommandAsync(guard + $" && test ! -L '{path}' && test ! -L '{temporary}' && test \"$(wc -c < '{temporary}')\" -eq {bytes.Length} && test \"$(sha256sum '{temporary}' | awk '{{print $1}}')\" = '{Hash(bytes.Span)}' && mv -f '{temporary}' '{path}'", ct);
        }
        finally
        {
            using var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await channel.CommandAsync(cleanup, cleanupTimeout.Token); }
            catch { /* Remaining partial belongs to the transaction; existing recovery handles it. */ }
        }
    }
}
