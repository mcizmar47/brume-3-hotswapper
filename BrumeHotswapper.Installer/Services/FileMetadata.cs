using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

public static class FileMetadata
{
    public static IReadOnlyDictionary<string,string> Commands(string path)
    {
        if (!DeploymentPlanning.Paths.Contains(path)) throw new SafeFailure("Unrecognized metadata path.");
        string q = ConfigurationGenerator.Quote(path);
        return new Dictionary<string,string> {
            ["symlink"] = $"if [ -L {q} ]; then echo 1; else echo 0; fi",
            ["exists"] = $"if [ -e {q} ]; then echo 1; else echo 0; fi",
            ["regular"] = $"if [ -f {q} ]; then echo 1; else echo 0; fi",
            ["readable"] = $"if [ -r {q} ]; then echo 1; else echo 0; fi",
            ["uid"] = $"stat -c '%u' {q}", ["gid"] = $"stat -c '%g' {q}",
            ["mode"] = $"stat -c '%a' {q}", ["size"] = $"wc -c < {q}",
            ["sha256"] = $"sha256sum {q} | awk '{{print $1}}'"
        };
    }
    public static async Task<Dictionary<string,string>> ReadAsync(IRouterTransport router, string path, CancellationToken ct)
    {
        var fields = new Dictionary<string,string>();
        foreach (var (field, command) in Commands(path))
        {
            if (fields.GetValueOrDefault("exists") == "0" && field is not "exists" and not "symlink") break;
            try {
                var value = (await router.ExecuteAsync(command, ct)).Trim();
                fields[field] = Regex.IsMatch(value, field == "sha256" ? "^[a-fA-F0-9]{64}$" : "^[0-9]{1,20}$") ? value : "invalid";
            } catch (OperationCanceledException) { throw; }
            catch { fields[field] = "unavailable"; }
        }
        return fields;
    }
    public static bool SafeMode(string path, string mode) => Regex.IsMatch(mode, "^[0-7]{3,4}$") &&
        (Convert.ToInt32(mode, 8) & 0xE12) == 0 && (path != "/usr/bin/rtp2.sh" || Convert.ToInt32(mode, 8) == 493);
    public static FileState Validate(string path, IReadOnlyDictionary<string,string> fields)
    {
        string Get(string key) => fields.GetValueOrDefault(key, "missing");
        if (Get("symlink") != "0") throw new SafeFailure("Target symlink status is unsafe or unknown.");
        if (Get("exists") == "0" && path != "/usr/bin/rtp2.sh") return new(path, "", "", false);
        foreach (var key in new[] {"exists", "regular", "readable"})
            if (Get(key) != "1") throw new SafeFailure("Target metadata failed: " + key + ".");
        foreach (var key in new[] {"uid", "gid"})
            if (Get(key) != "0") throw new SafeFailure("Target must have root ownership: " + key + ".");
        if (!SafeMode(path, Get("mode"))) throw new SafeFailure("Target permission mode is unsafe or unsupported.");
        if (!long.TryParse(Get("size"), out long size) || size < 0 || !Regex.IsMatch(Get("sha256"), "^[a-fA-F0-9]{64}$"))
            throw new SafeFailure("Target size or SHA-256 could not be verified.");
        return new(path, Get("sha256").ToLowerInvariant(), Get("mode"), true);
    }
}
