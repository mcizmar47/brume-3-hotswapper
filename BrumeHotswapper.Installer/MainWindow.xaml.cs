using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.ViewModels;
using Microsoft.Win32;

namespace BrumeHotswapper.Installer;

public class PageVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type type, object parameter, CultureInfo culture) => value is int page && page.ToString() == parameter.ToString() ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type type, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
public partial class MainWindow : Window
{
    private readonly WizardViewModel vm;
    private Point start;
    public MainWindow()
    {
        InitializeComponent();
        vm = new((address, fingerprint) => Dispatcher.Invoke(() => MessageBox.Show(this,
            $"SSH host: {address}\n\n{fingerprint}\n\nVerify this fingerprint with your router before trusting it. Trust this key for this session? A changed key will be rejected.",
            "Verify SSH host key", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes));
        DataContext = vm;
        Closed += (_, _) => { RouterPassword.Clear(); vm.Dispose(); };
    }
    // UI adapters only. Credentials pass to the session; discovery and commands live in services.
    private async void FindRouter(object sender, RoutedEventArgs e) { try { await vm.ConnectAsync(RouterPassword.Password, false); } finally { RouterPassword.Clear(); } }
    private async void TryRouter(object sender, RoutedEventArgs e) { try { await vm.ConnectAsync(RouterPassword.Password, true); } finally { RouterPassword.Clear(); } }
    private void CopyReport(object sender, RoutedEventArgs e)
    { try { Clipboard.SetText(vm.Report); } catch { MessageBox.Show(this, "The clipboard is busy. Try again."); } }
    private void SaveReport(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "Text report|*.txt", FileName = "brume-install-report.txt" };
        if (dialog.ShowDialog(this) != true) return;
        try { File.WriteAllText(dialog.FileName, vm.Report); } catch { MessageBox.Show(this, "Could not save the report to that location."); }
    }
    private void CardMouseDown(object sender, MouseButtonEventArgs e) => start = e.GetPosition(null);
    private void CardMouseMove(object sender, MouseEventArgs e)
    {
        var position = e.GetPosition(null);
        if (e.LeftButton != MouseButtonState.Pressed || (Math.Abs(position.X - start.X) < SystemParameters.MinimumHorizontalDragDistance && Math.Abs(position.Y - start.Y) < SystemParameters.MinimumVerticalDragDistance)) return;
        if (sender is ListBox list && list.SelectedItem is VpnLocationGroup group) DragDrop.DoDragDrop(list, group, DragDropEffects.Move);
    }
    private void CardDragOver(object sender, DragEventArgs e) { e.Effects = e.Data.GetDataPresent(typeof(VpnLocationGroup)) ? DragDropEffects.Move : DragDropEffects.None; e.Handled = true; }
    private void CardDrop(object sender, DragEventArgs e)
    {
        if (sender is not ListBox list || list.DataContext is not TierColumn tier || e.Data.GetData(typeof(VpnLocationGroup)) is not VpnLocationGroup group) return;
        int index = tier.Locations.Count;
        for (int i = 0; i < list.Items.Count; i++)
            if (list.ItemContainerGenerator.ContainerFromIndex(i) is ListBoxItem item && e.GetPosition(item).Y < item.ActualHeight / 2) { index = i; break; }
        vm.Move(group, tier, index); e.Handled = true;
    }
}
