using System.IO;
using Renci.SshNet.Common;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;
public static class FirmwareRead
{
    public const int MaximumBytes = 512_000;
    public static async Task<byte[]> CopyBoundedAsync(Stream input, CancellationToken ct)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        try
        {
            int count;
            while ((count = await input.ReadAsync(buffer, ct)) > 0)
            {
                if (output.Length + count > MaximumBytes) throw new SafeFailure("Firmware read exceeds the preflight limit.");
                await output.WriteAsync(buffer.AsMemory(0, count), ct);
            }
            return output.ToArray();
        }
        finally { Array.Clear(buffer); if (output.TryGetBuffer(out var segment)) Array.Clear(segment.Array!); }
    }
    public static string FailureCategory(Exception e) => e switch
    {
        SshAuthenticationException => "SSH authentication rejected (details withheld).",
        SshConnectionException => "SSH transport failure (details withheld).",
        SftpPermissionDeniedException => "SFTP permission denied.",
        SftpPathNotFoundException => "SFTP path not found.",
        SshException when e.Message.Contains("subsystem", StringComparison.OrdinalIgnoreCase) => "SFTP subsystem request/initialization failed (details withheld).",
        SshException => "SSH/SFTP protocol failure; exact server reason is not established.",
        _ => "Unclassified read failure; raw details withheld."
    };
}
