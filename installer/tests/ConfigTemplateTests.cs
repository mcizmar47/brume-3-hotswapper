using System.IO;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Tests;

public class ConfigTemplateTests
{
    [Fact] public void PrivateConfigPreservesEveryDefault()
    {
        var template = ConfigTemplates.Read("hotswapper.conf");
        Assert.Equal(File.ReadAllText(Path.Combine(RepositoryFiles.Root, "config", "hotswapper.conf")).Replace("\r\n", "\n"), template);
        var c = InstallerFixture.Config() with { Notifications = true, NtfyUrl = "https://ntfy.sh/test-topic" };
        Assert.Equal(template.Replace("TUNNEL_ID=''", $"TUNNEL_ID='{c.Profile.TunnelId}'")
            .Replace("GROUP_ID=''", $"GROUP_ID='{c.Profile.GroupId}'")
            .Replace("NTFY_URL=''", "NTFY_URL='https://ntfy.sh/test-topic'"), ConfigurationGenerator.PrivateConfig(c));
        Assert.DoesNotContain("DETECTOR_DELAY_US", template);
        Assert.Contains("DETECTOR_PERIOD_MS=400\n", template);
        Assert.Contains("FAST_PROBE_WINDOW_US=200000\n", template);
        Assert.Contains("FAST_FAILURE_THRESHOLD=2\n", template);
        Assert.Contains("READY_MAX_AGE_MS=5000\n", template);
        Assert.Contains("STANDBY_CHECK_MS=4000\n", template);
    }

    [Theory]
    [InlineData("TUNNEL_ID")][InlineData("GROUP_ID")][InlineData("NTFY_URL")]
    [InlineData("REBOOT_WINDOW_START")][InlineData("REBOOT_WINDOW_END")]
    public void RequiredFieldMustAppearExactlyOnce(string key)
    {
        Assert.Throws<SafeFailure>(() => ConfigTemplates.Replace("# " + key + "=1\n", (key, "2")));
        Assert.Throws<SafeFailure>(() => ConfigTemplates.Replace($"{key}=1\n{key}=2\n", (key, "3")));
    }

    [Fact] public void SubstitutionPreservesUnknownFieldsAndComments()
    {
        const string template = "# hours\nREBOOT_WINDOW_START=3\nFUTURE_SETTING='keep me'\nREBOOT_WINDOW_END=14\n";
        Assert.Equal(template.Replace("START=3", "START=8").Replace("END=14", "END=20"),
            ConfigTemplates.Replace(template, ("REBOOT_WINDOW_START", "8"), ("REBOOT_WINDOW_END", "20")));
    }
}
