using System.Diagnostics;
using System.Globalization;

using Aprillz.MewUI;
using Aprillz.MewUI.Controls;

Win32Platform.Register();
GdiBackend.Register();
Application.SetDefaultPlatformHost("win32");
Application.SetDefaultGraphicsFactory("gdi");

var initialSnapshot = CaptureSnapshot();
var currentSnapshot = initialSnapshot;
var statusText = new ObservableValue<string>(initialSnapshot.Status);
var portFilterText = new ObservableValue<string>(string.Empty);
var portHighlightColor = Color.FromRgb(245, 150, 45);

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
                        Content = BuildSnapshotBody(currentSnapshot, portFilterText.Value)
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
                        .Spacing(6)
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
                                .FontSize(11),
                            new StackPanel()
                                .Horizontal()
                                .Spacing(10)
                                .Children(
                                    new Label()
                                        .Text("Search")
                                        .CenterVertical(),
                                    new TextBox()
                                        .Width(280)
                                        .OnTextChanged(text =>
                                        {
                                            portFilterText.Value = text;
                                            UpdateSnapshotView();
                                        })))));
}

Element BuildSnapshotBody(SnapshotState snapshot, string portFilter)
{
    if (snapshot.ErrorMessage is not null)
    {
        return BuildInfoCard("Port scan failed", snapshot.ErrorMessage);
    }

    if (snapshot.Processes.Count == 0)
    {
        return BuildInfoCard("Nothing open", "No listening TCP or bound UDP ports were found.");
    }

    var filteredProcesses = FilterProcesses(snapshot.Processes, portFilter);
    if (filteredProcesses.Count == 0)
    {
        var normalizedFilter = NormalizePortFilter(portFilter);
        return BuildInfoCard(
            "No matching ports",
            $"No apps matched port filter \"{normalizedFilter}\". Partial matches are supported.");
    }

    return new StackPanel()
        .Vertical()
        .Spacing(12)
        .Padding(16)
        .Children(filteredProcesses.Select(process => BuildProcessCard(process, portFilter)).ToArray());
}

Element BuildProcessCard(PortProcessInfo processInfo, string portFilter)
{
    var matchCount = processInfo.PortBindings.Count(binding => MatchesPortFilter(binding, portFilter));
    var portSummary = $"{processInfo.PortBindings.Count} open port{(processInfo.PortBindings.Count == 1 ? string.Empty : "s")}";
    if (matchCount > 0)
    {
        portSummary += $" | {matchCount} match{(matchCount == 1 ? string.Empty : "es")}";
    }

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
                                .Text(portSummary)
                                .FontSize(11),
                            BuildPortBindings(processInfo.PortBindings, portFilter))));
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
    currentSnapshot = CaptureSnapshot();
    statusText.Value = currentSnapshot.Status;
    UpdateSnapshotView();
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

void UpdateSnapshotView()
{
    listHost.Content = BuildSnapshotBody(currentSnapshot, portFilterText.Value);
}

Element BuildPortBindings(IReadOnlyList<PortBinding> bindings, string portFilter)
{
    return new WrapPanel()
        .Spacing(8)
        .Children(bindings.Select(binding => BuildPortChip(binding, MatchesPortFilter(binding, portFilter))).ToArray());
}

Element BuildPortChip(PortBinding binding, bool isMatch)
{
    var portText = new TextBlock()
        .Text(binding.Port.ToString(CultureInfo.InvariantCulture))
        .FontSize(11)
        .Bold();

    if (isMatch)
    {
        portText.Foreground(portHighlightColor);
    }

    return new Border()
        .Padding(8, 5)
        .CornerRadius(999)
        .WithTheme((theme, border) =>
        {
            var chipBackground = theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.18);
            border.Background(isMatch ? chipBackground.Lerp(portHighlightColor, 0.22) : chipBackground);
            border.BorderBrush(isMatch ? portHighlightColor : theme.Palette.ControlBorder);
            border.BorderThickness = 1;
        })
        .Child(
            new StackPanel()
                .Horizontal()
                .Spacing(6)
                .Children(
                    new TextBlock()
                        .Text($"{(binding.Protocol == PortProtocol.Tcp ? "TCP" : "UDP")}{(binding.IsIpv6 ? "6" : string.Empty)}")
                        .FontSize(11),
                    portText));
}

IReadOnlyList<PortProcessInfo> FilterProcesses(IReadOnlyList<PortProcessInfo> processes, string portFilter)
{
    var normalizedFilter = NormalizePortFilter(portFilter);
    if (normalizedFilter.Length == 0)
    {
        return processes;
    }

    return processes
        .Where(process => process.PortBindings.Any(binding => MatchesPortFilter(binding, normalizedFilter)))
        .ToArray();
}

bool MatchesPortFilter(PortBinding binding, string portFilter)
{
    var normalizedFilter = NormalizePortFilter(portFilter);
    return normalizedFilter.Length != 0
        && binding.Port.ToString(CultureInfo.InvariantCulture).Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase);
}

string NormalizePortFilter(string portFilter)
    => portFilter.Trim();

string BuildStatus(int processCount)
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
