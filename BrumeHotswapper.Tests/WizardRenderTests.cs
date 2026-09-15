using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using BrumeHotswapper.Installer;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.ViewModels;

namespace BrumeHotswapper.Tests;

public class WizardRenderTests
{
    [Fact]
    public void AllWizardPagesLoadAndRenderOnStaThread()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var window = new MainWindow();
                var vm = (WizardViewModel)window.DataContext; vm.Demo = true;
                vm.Tiers[1].Locations.Add(new("demo", "Germany / Frankfurt", [new("1", "Demo", "Germany / Frankfurt")]));
                vm.Tiers[2].Locations.Add(new("demo2", "Switzerland / Zurich", [new("2", "Demo", "Switzerland / Zurich")]));
                var content = (FrameworkElement)window.Content;
                var directory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../artifacts/ui"));
                Directory.CreateDirectory(directory);
                for (int page = 0; page < WizardViewModel.PageTitles.Length; page++)
                {
                    typeof(WizardViewModel).GetProperty(nameof(vm.Page))!.SetValue(vm, page);
                    Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.DataBind);
                    content.Measure(new Size(1040, 710)); content.Arrange(new Rect(0, 0, 1040, 710)); content.UpdateLayout();
                    var bitmap = new RenderTargetBitmap(1040, 710, 96, 96, PixelFormats.Pbgra32); bitmap.Render(content);
                    if (page is 0 or 5)
                    {
                        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
                        using var stream = File.Create(Path.Combine(directory, $"wizard-{page}.png")); encoder.Save(stream);
                    }
                    Assert.True(content.IsArrangeValid);
                }
                vm.Dispose(); window.Close();
            }
            catch (Exception e) { failure = e; }
            finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); Assert.True(thread.Join(TimeSpan.FromSeconds(30)));
        Assert.Null(failure);
    }
}
