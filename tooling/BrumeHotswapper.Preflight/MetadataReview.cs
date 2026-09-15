using System.Text.RegularExpressions;
namespace BrumeHotswapper.Preflight;
public static class MetadataReview
{
    public static IReadOnlyList<Check> Evaluate(string path, string output)
    {
        var rows = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).Select(x => x.Split('=', 2)).ToArray();
        if (rows.Any(x => x.Length != 2) || rows.GroupBy(x => x[0]).Any(g => g.Count() != 1))
            return [new("File " + path, "BLOCK", "Metadata response has missing labels, duplicate labels or extra lines; no ownership assumption made.")];
        var fields = rows.ToDictionary(x => x[0], x => x[1]);
        string Get(string key) => fields.GetValueOrDefault(key, "missing");
        var checks = new List<Check>();
        void Flag(string key, bool valid, string detail) => checks.Add(new("File " + path + " / " + key, valid ? "PASS" : "BLOCK", detail));
        Flag("symlink", Get("symlink") == "0", Get("symlink") == "0" ? "Not a symlink." : "Symlink or unknown link status; refuse replacement.");
        if (Get("exists") == "0")
        {
            bool generated = path is "/root/vpn-watch-locations.tsv" or "/root/reboot-guards.tsv";
            checks.Add(new("File " + path + " / existence", "WARN", generated ? "Expected legacy absence; generated during a separately authorized migration. Required after installation." : "Absent; no file modified."));
            return checks;
        }
        Flag("exists", Get("exists") == "1", Get("exists") == "1" ? "Exists." : "Existence not established.");
        Flag("regular", Get("regular") == "1", Get("regular") == "1" ? "Regular file." : "Not a regular file or type unknown.");
        Flag("readability", Get("readable") == "1", Get("readable") == "1" ? "Readable." : "Not readable or unknown.");
        foreach (var key in new[] { "uid", "gid" })
            Flag(key, Get(key) == "0", Regex.IsMatch(Get(key), @"^\d+$") ? key.ToUpperInvariant() + "=" + Get(key) + "; expected 0 (root)." : key.ToUpperInvariant() + " could not be parsed as numeric metadata.");
        string mode = Get("mode");
        if (!Regex.IsMatch(mode, "^[0-7]{3,4}$")) Flag("mode", false, Regex.IsMatch(mode, "^[0-9]+$") ? "Unsupported numeric mode representation: " + mode : "Mode is missing or unparseable.");
        else
        {
            int bits = Convert.ToInt32(mode, 8);
            bool unsafeBits = (bits & 0xE12) != 0; // setuid/setgid/sticky and group/other write
            string desired = path == "/usr/bin/rtp2.sh" ? "755 (firmware expectation; preserve verified firmware mode)" : path.EndsWith(".sh") ? "700" : "600";
            bool exact = path == "/usr/bin/rtp2.sh" ? bits == 493 : bits == (path.EndsWith(".sh") ? 448 : 384);
            checks.Add(new("File " + path + " / mode", (unsafeBits || (path == "/usr/bin/rtp2.sh" && !exact)) ? "BLOCK" : exact ? "PASS" : "WARN", "Observed " + mode + "; expected " + desired + (unsafeBits ? "; unsafe write/special permission bits." : exact ? "." : "; legacy difference requires deliberate normalization/review during authorized installation, not preflight.")));
        }
        Flag("hash", Regex.IsMatch(Get("sha256"), "^[a-fA-F0-9]{64}$"), Regex.IsMatch(Get("sha256"), "^[a-fA-F0-9]{64}$") ? "Readable SHA-256 in valid format; content/hash withheld for private configuration." : "SHA-256 missing or invalid.");
        Flag("size", long.TryParse(Get("size"), out long size) && size >= 0, long.TryParse(Get("size"), out size) ? "Bytes: " + size : "Size could not be parsed.");
        return checks;
    }
}
