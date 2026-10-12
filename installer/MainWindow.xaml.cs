using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Navigation;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.ViewModels;
using Microsoft.Win32;

namespace BrumeHotswapper.Installer;

public class PageVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type type, object parameter, CultureInfo culture) =>
        value is int page && page.ToString() == parameter?.ToString() ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type type, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public partial class MainWindow : Window
{
    private readonly WizardViewModel vm;
    private Point start;

    public MainWindow()
    {
        InitializeComponent();
        vm = new WizardViewModel((address, fingerprint) => Dispatcher.Invoke(() => MessageBox.Show(this,
            $"Check that this SSH fingerprint belongs to your router at {address}:\n\n{fingerprint}\n\nTrust it for this connection? Choose No if you cannot verify it.",
            "Verify SSH host key", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes));
        DataContext = vm;
        Closing += (_, e) =>
        {
            if (vm.Page != 5 || !vm.Busy) return;
            e.Cancel = true;
            MessageBox.Show(this, "Installation is still running. Wait for it to finish before closing the installer.");
        };
        Closed += (_, _) => { RouterPassword.Clear(); vm.Dispose(); };
    }
    private void CloseInstaller(object sender, RoutedEventArgs e) => Close();
    private async void ToggleConnection(object sender, RoutedEventArgs e)
    {
        if (vm.Connected)
        {
            vm.Disconnect();
            RouterPassword.Clear();
            return;
        }
        try { await vm.ConnectAsync(RouterPassword.Password); }
        finally { RouterPassword.Clear(); }
    }
    private void ConnectPageVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.NewValue is true && vm != null && !vm.Connected)
            Dispatcher.BeginInvoke(new Action(() => { RouterPassword.Focus(); Keyboard.Focus(RouterPassword); }));
    }
    private void OpenLink(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            if (e.Uri.Scheme is "http" or "https")
                Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch { MessageBox.Show(this, "Could not open the browser. Please open the router's Admin Panel manually."); }
        e.Handled = true;
    }
    private static readonly Regex Digits = new(@"^[0-9]{1,2}$", RegexOptions.Compiled);
    private void HourInput(object sender, TextCompositionEventArgs e) =>
        e.Handled = !Regex.IsMatch(e.Text, @"^[0-9]+$");
    private void HourPaste(object sender, DataObjectPastingEventArgs e)
    {
        if (!e.SourceDataObject.GetDataPresent(DataFormats.UnicodeText) ||
            e.SourceDataObject.GetData(DataFormats.UnicodeText) is not string text || !Digits.IsMatch(text))
            e.CancelCommand();
    }
    private void RemoveGuard(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: GuardIpEntry entry }) vm.RemoveGuard(entry);
    }
    private void SaveInstallationLog(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "Text file|*.txt", FileName = "hotswapper-installation-log.txt" };
        if (dialog.ShowDialog(this) != true) return;
        try { File.WriteAllText(dialog.FileName, vm.InstallationLog); }
        catch (IOException) { MessageBox.Show(this, "Could not save the installation log.", "Save log", MessageBoxButton.OK, MessageBoxImage.Error); }
        catch (UnauthorizedAccessException) { MessageBox.Show(this, "Access denied when saving the installation log.", "Save log", MessageBoxButton.OK, MessageBoxImage.Error); }
    }
    private void CardMouseDown(object sender, MouseButtonEventArgs e) => start = e.GetPosition(null);
    private void CardMouseMove(object sender, MouseEventArgs e)
    {
        var position = e.GetPosition(null);
        if (e.LeftButton != MouseButtonState.Pressed ||
            (Math.Abs(position.X - start.X) < SystemParameters.MinimumHorizontalDragDistance &&
             Math.Abs(position.Y - start.Y) < SystemParameters.MinimumVerticalDragDistance)) return;
        if (sender is ListBox list && list.SelectedItem is VpnLocationGroup group)
            DragDrop.DoDragDrop(list, group, DragDropEffects.Move);
    }
    private void CardDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(typeof(VpnLocationGroup)) ? DragDropEffects.Move : DragDropEffects.None;
        e.Handled = true;
    }
    private void CardDrop(object sender, DragEventArgs e)
    {
        if (sender is not ListBox list || list.DataContext is not TierColumn tier ||
            e.Data.GetData(typeof(VpnLocationGroup)) is not VpnLocationGroup group) return;
        int index = tier.Locations.Count;
        for (int i = 0; i < list.Items.Count; i++)
            if (list.ItemContainerGenerator.ContainerFromIndex(i) is ListBoxItem item &&
                e.GetPosition(item).Y < item.ActualHeight / 2) { index = i; break; }
        vm.Move(group, tier, index);
        e.Handled = true;
    }
}
