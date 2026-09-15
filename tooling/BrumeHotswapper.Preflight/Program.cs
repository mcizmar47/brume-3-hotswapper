using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;

public static class Program
{
    [STAThread] public static void Main(string[] args)
    {
        var app = new Application();
        try {
            if (args.Contains("--help")) { MessageBox.Show("Launch directly for the focused read-only preflight. Select the local Brume archive folder if requested.\nOptional: <repository> <archive-directory> <sh.exe> <result.json> [--follow-up]\nNo credentials are accepted on the command line.", "Preflight help"); return; }
            string repository, archive, shell, result;
            bool followUp = true;
            if (args.Length is 4 or 5) {
                (repository, archive, shell, result) = (args[0], args[1], args[2], args[3]);
                followUp = args.Length == 5 && args[4] == "--follow-up";
            } else {
                if (args.Length != 0 && !args.SequenceEqual(new[]{"--follow-up"})) throw new IOException("Unsupported arguments. Use --help.");
                repository = FindRepository() ?? throw new IOException("Cannot locate the repository. Launch from its build output or supply paths with --help.");
                var picker = new Microsoft.Win32.OpenFolderDialog { Title = "Select the historical Brume 3 archive folder (containing brume_dump.zip)" };
                if (picker.ShowDialog() != true) { MessageBox.Show("A local archive is required for the firmware comparison. No router connection was made."); return; }
                archive = picker.FolderName;
                shell = FindShell() ?? throw new IOException("Cannot find a local Git sh.exe. Supply its path using the documented arguments.");
                result = Path.Combine(repository, "artifacts", "preflight", "result-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".json");
            }
            if (!File.Exists(Path.Combine(repository, "BrumeHotswapper.slnx")) || !File.Exists(Path.Combine(archive, "brume_dump.zip")) || !File.Exists(shell))
                throw new IOException("Required repository, brume_dump.zip archive, or local shell is missing. Use --help to supply valid paths.");
            app.Run(new PreflightWindow(repository, archive, shell, Path.GetFullPath(result), followUp));
        } catch (IOException e) { MessageBox.Show(e.Message, "Preflight cannot start", MessageBoxButton.OK, MessageBoxImage.Error); }
          catch { MessageBox.Show("Preflight could not start. Verify local evidence paths using --help.", "Preflight cannot start"); }
    }
    public static string? FindRepository()
    {
        foreach (var start in new[]{AppContext.BaseDirectory, Environment.CurrentDirectory})
            for (var d = new DirectoryInfo(start); d != null; d = d.Parent)
                if (File.Exists(Path.Combine(d.FullName, "BrumeHotswapper.slnx"))) return d.FullName;
        return null;
    }
    private static string? FindShell()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "usr", "bin", "sh.exe"),
            Path.Combine(home, ".cache", "codex-runtimes", "codex-primary-runtime", "dependencies", "native", "git", "usr", "bin", "sh.exe")}.FirstOrDefault(File.Exists);
    }
}
public sealed class PreflightWindow : Window
{
    private readonly TextBox address = new() { MinWidth = 250, Margin = new Thickness(0, 4, 0, 12) };
    private readonly PasswordBox password = new() { MinWidth = 250, Margin = new Thickness(0, 4, 0, 14) };
    private readonly TextBox output = new() { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MinHeight = 280 };
    private readonly Button run = new() { Content = "Connect and run READ-ONLY preflight", Padding = new Thickness(12), Margin = new Thickness(0, 0, 0, 12) };
    private readonly List<Check> checks = [];
    private readonly CancellationTokenSource cancellation = new();
    public PreflightWindow(string repository, string archive, string shell, string resultPath, bool followUp = false)
    {
        Title = "Brume 3 — READ-ONLY preflight"; Width = 780; Height = 720; WindowStartupLocation = WindowStartupLocation.CenterScreen;
        if (followUp) run.Content = "Connect: firmware / routing / metadata ONLY";
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = "Read-only router preflight", FontSize = 26, Margin = new Thickness(0, 0, 0, 14) });
        panel.Children.Add(new TextBlock { Text = "Uses the installer's SSH authentication and inspection code. No installation, patching, uploads, UCI changes, service actions or notifications. Enter credentials here only; they are never saved.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) });
        panel.Children.Add(new TextBlock { Text = "Router IPv4 address" }); panel.Children.Add(address);
        panel.Children.Add(new TextBlock { Text = "Router administrator password (root SSH)" }); panel.Children.Add(password);
        panel.Children.Add(run); panel.Children.Add(output); Content = panel;
        Loaded += async (_, _) => {
            run.IsEnabled = false;
            try {
                var candidates = new List<string>();
                foreach (var candidate in RouterDiscovery.Candidates())
                    if (await RouterDiscovery.HasSshAsync(candidate, cancellation.Token)) candidates.Add(candidate);
                if (candidates.Count == 1) { address.Text = candidates[0]; output.AppendText("One SSH gateway candidate found. Authentication will verify device identity.\n"); }
                else output.AppendText("Gateway discovery found zero or multiple SSH candidates. Enter the router IPv4 address manually.\n");
            } catch { output.AppendText("Gateway discovery unavailable; enter the router IPv4 address manually.\n"); }
            finally { run.IsEnabled = true; }
        };
        Closed += (_, _) => cancellation.Cancel();
        void Report(Check check)
        {
            Dispatcher.Invoke(() => { checks.Add(check); output.AppendText($"{check.Status}: {check.Name} — {check.Detail}\n"); output.ScrollToEnd();
                Directory.CreateDirectory(Path.GetDirectoryName(resultPath)!);
                File.WriteAllText(resultPath, JsonSerializer.Serialize(new { State = "Running", Checks = checks }, new JsonSerializerOptions { WriteIndented = true })); });
        }
        run.Click += async (_, _) =>
        {
            run.IsEnabled = false; checks.Clear(); output.Clear();
            using var session = new SshRouterSession((_, fingerprint) => Dispatcher.Invoke(() => MessageBox.Show(this,
                "Confirm this router's SSH host fingerprint before authentication:\n\n" + fingerprint + "\n\nTrust for this session only?", "SSH host verification", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes));
            try
            {
                string secret = password.Password; password.Clear();
                var connect = session.ConnectAsync(address.Text.Trim(), secret, cancellation.Token); secret = "";
                var identity = await connect;
                Report(new("Authentication", "PASS", "Authenticated using installer SSH.NET flow and interactive host trust. Credentials remain session-only."));
                var runner = new Runner(session, repository, archive, shell, Report);
                if (followUp) await runner.RunFollowUpAsync(identity, cancellation.Token);
                else await runner.RunAsync(identity, cancellation.Token);
                File.WriteAllText(resultPath, JsonSerializer.Serialize(new { State = "Complete", Checks = checks }, new JsonSerializerOptions { WriteIndented = true }));
                output.AppendText("\nFinished. Connection closed. No router changes were requested.\n");
            }
            catch { Report(new("Preflight", "BLOCK", "Authentication, cancellation or preflight failed. Credentials and raw errors withheld."));
                File.WriteAllText(resultPath, JsonSerializer.Serialize(new { State = "Stopped", Checks = checks }, new JsonSerializerOptions { WriteIndented = true })); }
            finally { session.Dispose(); password.Clear(); run.IsEnabled = true; }
        };
    }
}
