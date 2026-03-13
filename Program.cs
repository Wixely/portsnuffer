using System.Diagnostics;

using Aprillz.MewUI;
using Aprillz.MewUI.Controls;

Win32Platform.Register();
GdiBackend.Register();
Application.SetDefaultPlatformHost("win32");
Application.SetDefaultGraphicsFactory("gdi");

var initialSnapshot = CaptureSnapshot();
var statusText = new ObservableValue<string>(initialSnapshot.Status);

Window window = null!;
ContentControl listHost = null!;

var mainWindow = new Window()
    .Resizable(1120, 760)
    .Ref(out window)
    .Title("portsnuffer")
    .Padding(0)
    .Content(
        new DockPanel()
            .LastChildFill()
            .Children(
                BuildHeader().DockTop(),
                new ScrollViewer
                {
                    VerticalScroll = ScrollMode.Auto,
                    HorizontalScroll = ScrollMode.Disabled,
                    Content = new ContentControl
                    {
                        Content = BuildSnapshotBody(initialSnapshot)
                    }.Ref(out listHost)
                }));

Application.Run(mainWindow);

FrameworkElement BuildHeader()
{
    return new Border()
        .Padding(20, 18)
        .WithTheme((theme, border) =>
        {
            border.Background(theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.25));
            border.BorderBrush(theme.Palette.ControlBorder);
            border.BorderThickness = 1;
        })
        .Child(
            new DockPanel()
                .Children(
                    new StackPanel()
                        .DockRight()
                        .Horizontal()
                        .Spacing(10)
                        .Children(
                            new Button()
                                .Content("Refresh")
                                .Width(100)
                                .OnClick(RefreshSnapshot),
                            new Button()
                                .Content("Quit")
                                .Width(80)
                                .OnClick(Application.Quit)),
                    new StackPanel()
                        .Vertical()
                        .Spacing(4)
                        .Children(
                            new Label()
                                .Text("portsnuffer")
                                .FontSize(22)
                                .Bold()
                                .WithTheme((theme, label) => label.Foreground(theme.Palette.Accent)),
                            new Label()
                                .Text("Listening TCP and bound UDP ports grouped by process.")
                                .FontSize(12),
                            new Label()
                                .BindText(statusText)
                                .FontSize(11))));
}

Element BuildSnapshotBody(SnapshotState snapshot)
{
    if (snapshot.ErrorMessage is not null)
    {
        return BuildInfoCard("Port scan failed", snapshot.ErrorMessage);
    }

    if (snapshot.Processes.Count == 0)
    {
        return BuildInfoCard("Nothing open", "No listening TCP or bound UDP ports were found.");
    }

    return new StackPanel()
        .Vertical()
        .Spacing(12)
        .Padding(16)
        .Children(snapshot.Processes.Select(BuildProcessCard).ToArray());
}

Element BuildProcessCard(PortProcessInfo processInfo)
{
    return new Border()
        .Padding(14)
        .Margin(0, 0, 0, 4)
        .CornerRadius(12)
        .WithTheme((theme, border) =>
        {
            border.Background(theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.12));
            border.BorderBrush(theme.Palette.ControlBorder);
            border.BorderThickness(theme.Metrics.ControlBorderThickness);
        })
        .Child(
            new DockPanel()
                .Spacing(12)
                .Children(
                    BuildActionArea(processInfo).DockRight(),
                    new StackPanel()
                        .Vertical()
                        .Spacing(4)
                        .Children(
                            new Label()
                                .Text(processInfo.DisplayName)
                                .FontSize(15)
                                .Bold(),
                            new Label()
                                .Text($"{processInfo.PortBindings.Count} open port{(processInfo.PortBindings.Count == 1 ? string.Empty : "s")}")
                                .FontSize(11),
                            new Label()
                                .Text(string.Join("   ", processInfo.PortBindings.Select(static binding => binding.DisplayText)))
                                .TextWrapping(TextWrapping.Wrap))));
}

Element BuildActionArea(PortProcessInfo processInfo)
{
    var area = new StackPanel()
        .Vertical()
        .Spacing(6)
        .CenterVertical()
        .Width(110);

    if (processInfo.CanTerminate)
    {
        area.Children(
            new Button()
                .Content("Kill")
                .OnClick(() => KillProcess(processInfo)));
    }
    else
    {
        area.Children(
            new Label()
                .Text("Protected")
                .FontSize(11)
                .CenterHorizontal());
    }

    return area;
}

Element BuildInfoCard(string title, string message)
{
    return new StackPanel()
        .Vertical()
        .Padding(20)
        .Children(
            new Border()
                .Padding(18)
                .CornerRadius(12)
                .WithTheme((theme, border) =>
                {
                    border.Background(theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.12));
                    border.BorderBrush(theme.Palette.ControlBorder);
                    border.BorderThickness(theme.Metrics.ControlBorderThickness);
                })
                .Child(
                    new StackPanel()
                        .Vertical()
                        .Spacing(6)
                        .Children(
                            new Label()
                                .Text(title)
                                .FontSize(18)
                                .Bold(),
                            new Label()
                                .Text(message)
                                .TextWrapping(TextWrapping.Wrap))));
}

void RefreshSnapshot()
{
    var snapshot = CaptureSnapshot();
    statusText.Value = snapshot.Status;
    listHost.Content = BuildSnapshotBody(snapshot);
}

void KillProcess(PortProcessInfo processInfo)
{
    var confirmation = MessageBox.Show(
        window.Handle,
        $"Kill {processInfo.DisplayName}?",
        "portsnuffer",
        MessageBoxButtons.YesNo,
        MessageBoxIcon.Warning);

    if (confirmation != MessageBoxResult.Yes)
    {
        return;
    }

    try
    {
        using var process = Process.GetProcessById(processInfo.ProcessId);
        process.Kill();
        process.WaitForExit(2000);

        statusText.Value = $"Terminated {processInfo.DisplayName} at {DateTime.Now:HH:mm:ss}.";
        RefreshSnapshot();
    }
    catch (Exception ex)
    {
        statusText.Value = $"Failed to terminate {processInfo.DisplayName}: {ex.Message}";
        _ = MessageBox.Show(
            window.Handle,
            ex.Message,
            "Unable to terminate process",
            MessageBoxButtons.Ok,
            MessageBoxIcon.Error);
        RefreshSnapshot();
    }
}

SnapshotState CaptureSnapshot()
{
    try
    {
        var processes = PortInventory.Snapshot();
        return new SnapshotState(processes, null, BuildStatus(processes.Count));
    }
    catch (Exception ex)
    {
        return new SnapshotState(
            Array.Empty<PortProcessInfo>(),
            ex.Message,
            $"Scan failed at {DateTime.Now:HH:mm:ss}.");
    }
}

static string BuildStatus(int processCount)
{
    var timestamp = DateTime.Now.ToString("HH:mm:ss");
    return processCount == 0
        ? $"No listening TCP or bound UDP ports found at {timestamp}."
        : $"Found {processCount} process{(processCount == 1 ? string.Empty : "es")} with open ports at {timestamp}.";
}

readonly record struct SnapshotState(
    IReadOnlyList<PortProcessInfo> Processes,
    string? ErrorMessage,
    string Status);
