using System.Text.RegularExpressions;
namespace BrumeHotswapper.Installer.Core;
public static class NtfyTopic
{
    public static string Normalize(string input)
    {
        string topic = input.Trim();
        const string prefix = "https://ntfy.sh/";
        if (topic.StartsWith(prefix, StringComparison.Ordinal)) topic = topic[prefix.Length..];
        if (!Regex.IsMatch(topic, @"\A[A-Za-z0-9_-]{1,64}\z"))
            throw new SafeFailure("Enter an ntfy topic (letters, digits, underscore or hyphen) or its https://ntfy.sh/ URL.");
        return prefix + topic;
    }
}
