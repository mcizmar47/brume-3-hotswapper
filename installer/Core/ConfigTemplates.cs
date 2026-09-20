using System.IO;
using System.Text.RegularExpressions;

namespace BrumeHotswapper.Installer.Core;

public static class ConfigTemplates
{
    public static string Read(string name)
    {
        try { return File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "RouterAssets", name)).Replace("\r\n", "\n"); }
        catch (IOException) { throw new SafeFailure("A packaged configuration template is missing or unreadable."); }
        catch (UnauthorizedAccessException) { throw new SafeFailure("A packaged configuration template is unreadable."); }
    }

    private static Regex Field(string key) => new("^" + Regex.Escape(key) + "=([^\\r\\n]*)$", RegexOptions.Multiline);

    public static string Replace(string template, params (string Key, string Value)[] fields)
    {
        template = template.Replace("\r\n", "\n");
        foreach (var (key, value) in fields)
        {
            var field = Field(key);
            if (field.Matches(template).Count != 1)
                throw new SafeFailure($"Configuration template must contain exactly one {key} assignment.");
            template = field.Replace(template, _ => key + "=" + value);
        }
        return template;
    }

    public static (int Start, int End) MaintenanceHours
    {
        get
        {
            var template = Read("housekeeping.conf");
            int Hour(string key)
            {
                var matches = Field(key).Matches(template);
                if (matches.Count != 1 || !Regex.IsMatch(matches[0].Groups[1].Value, "^[0-9]+$") ||
                    !int.TryParse(matches[0].Groups[1].Value, out var hour) || hour is < 0 or > 23)
                    throw new SafeFailure("Invalid packaged maintenance hours.");
                return hour;
            }
            var start = Hour("REBOOT_WINDOW_START");
            var end = Hour("REBOOT_WINDOW_END");
            if (start > end) throw new SafeFailure("Invalid packaged maintenance window.");
            return (start, end);
        }
    }
}
