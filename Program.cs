using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Reflection;

using Aprillz.MewUI;
using Aprillz.MewUI.Controls;

Win32Platform.Register();
Direct2DBackend.Register();
Application.SetDefaultPlatformHost("win32");
Application.SetDefaultGraphicsFactory("direct2d");

var initialSnapshot = CaptureSnapshot();
var currentSnapshot = initialSnapshot;
var currentConnectionSnapshot = new ConnectionSnapshotState(
    Array.Empty<TcpConnectionInfo>(),
    null,
    "Connections not scanned yet.");
var connectionsLoaded = false;
var activeView = ViewMode.Ports;
var refreshVersion = 0;
var dnsVersion = 0;
var searchUpdateVersion = 0;
var refreshInProgress = false;
var hostNameUpdateQueued = false;
var lastRefreshStarted = DateTime.MinValue;
var statusText = new ObservableValue<string>(initialSnapshot.Status);
var portFilterText = new ObservableValue<string>(string.Empty);
var portHighlightColor = Color.FromRgb(245, 150, 45);
var appIcon = LoadAppIcon();
var hostNameCache = new Dictionary<IPAddress, string?>();
var hostNameLookupsInFlight = new HashSet<IPAddress>();

Window window = null!;
ContentControl listHost = null!;

var mainWindow = new Window()
    .Resizable(1120, 760)
    .Ref(out window)
    .Title("portsnuffer")
    .OnBuild(window => window.Icon = appIcon)
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
        .Padding(12, 8)
        .WithTheme((theme, border) =>
        {
            border.Background(theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.25));
            border.BorderBrush(theme.Palette.ControlBorder);
            border.BorderThickness = 1;
        })
        .Child(
            new DockPanel()
                .Spacing(10)
                .Children(
                    new StackPanel()
                        .DockRight()
                        .Horizontal()
                        .Spacing(8)
                        .Children(
                            new Button()
                                .Content("Refresh")
                                .Width(86)
                                .OnClick(RefreshSnapshot),
                            new Button()
                                .Content("Quit")
                                .Width(68)
                                .OnClick(Application.Quit)),
                    new StackPanel()
                        .DockLeft()
                        .Horizontal()
                        .Spacing(6)
                        .Children(
                            new Button()
                                .Content("Ports")
                                .Width(82)
                                .OnClick(() => SwitchView(ViewMode.Ports)),
                            new Button()
                                .Content("Connections")
                                .Width(116)
                                .OnClick(() => SwitchView(ViewMode.Connections))),
                    new StackPanel()
                        .DockRight()
                        .Horizontal()
                        .Spacing(8)
                        .Children(
                            new Label()
                                .Text("Search")
                                .FontSize(11)
                                .CenterVertical(),
                            new TextBox()
                                .Width(220)
                                .OnTextChanged(OnSearchTextChanged)),
                    new StackPanel()
                        .Horizontal()
                        .Spacing(10)
                        .CenterVertical()
                        .Children(
                            new Label()
                                .BindText(statusText)
                                .FontSize(11)
                                .CenterVertical())));
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
        .Spacing(8)
        .Padding(10)
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
        .Padding(10)
        .Margin(0, 0, 0, 2)
        .CornerRadius(6)
        .WithTheme((theme, border) =>
        {
            border.Background(theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.12));
            border.BorderBrush(theme.Palette.ControlBorder);
            border.BorderThickness(theme.Metrics.ControlBorderThickness);
        })
        .Child(
            new DockPanel()
                .Spacing(10)
                .Children(
                    BuildActionArea(processInfo).DockRight(),
                    new StackPanel()
                        .Vertical()
                        .Spacing(6)
                        .Children(
                            new StackPanel()
                                .Horizontal()
                                .Spacing(10)
                                .Children(
                                    new Label()
                                        .Text(processInfo.DisplayName)
                                        .FontSize(14)
                                        .Bold()
                                        .CenterVertical(),
                                    new Label()
                                        .Text(portSummary)
                                        .FontSize(11)
                                        .CenterVertical()),
                            BuildPortBindings(processInfo.PortBindings, portFilter))));
}

Element BuildActionArea(PortProcessInfo processInfo)
{
    var area = new StackPanel()
        .Vertical()
        .CenterVertical()
        .Width(80);

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

Element BuildConnectionBody(ConnectionSnapshotState snapshot, string searchText)
{
    if (snapshot.ErrorMessage is not null)
    {
        return BuildInfoCard("Connection scan failed", snapshot.ErrorMessage);
    }

    if (snapshot.Connections.Count == 0)
    {
        return BuildInfoCard("No connections", "No active TCP connections were found.");
    }

    var filteredConnections = FilterConnections(snapshot.Connections, searchText);
    if (filteredConnections.Count == 0)
    {
        var normalizedFilter = NormalizePortFilter(searchText);
        return BuildInfoCard("No matching connections", $"No connections matched \"{normalizedFilter}\".");
    }

    return new StackPanel()
        .Vertical()
        .Spacing(8)
        .Padding(10)
        .Children(filteredConnections.Select(connection => BuildConnectionCard(connection, searchText)).ToArray());
}

Element BuildConnectionCard(TcpConnectionInfo connection, string searchText)
{
    var processLabel = new TextBlock()
        .Text(connection.DisplayName)
        .FontSize(14)
        .Bold();
    var statusLabel = new TextBlock()
        .Text($"{connection.Direction} | {connection.State}")
        .FontSize(11);
    var normalizedFilter = NormalizePortFilter(searchText);

    if (MatchesAnyText(normalizedFilter, connection.ProcessName, connection.ProcessId.ToString(CultureInfo.InvariantCulture)))
    {
        processLabel.Foreground(portHighlightColor);
    }

    if (MatchesAnyText(normalizedFilter, connection.Direction.ToString(), connection.State))
    {
        statusLabel.Foreground(portHighlightColor);
    }

    return new Border()
        .Padding(10)
        .Margin(0, 0, 0, 2)
        .CornerRadius(6)
        .WithTheme((theme, border) =>
        {
            border.Background(theme.Palette.ControlBackground.Lerp(theme.Palette.WindowBackground, 0.12));
            border.BorderBrush(theme.Palette.ControlBorder);
            border.BorderThickness(theme.Metrics.ControlBorderThickness);
        })
        .Child(
            new DockPanel()
                .Spacing(10)
                .Children(
                    BuildConnectionActionArea(connection).DockRight(),
                    new StackPanel()
                        .Vertical()
                        .Spacing(6)
                        .Children(
                            new StackPanel()
                                .Horizontal()
                                .Spacing(10)
                                .Children(
                                    processLabel,
                                    statusLabel),
                            new StackPanel()
                                .Horizontal()
                                .Spacing(14)
                                .Children(
                                    BuildEndpointBlock("Local", connection.LocalDisplayAddress, connection.LocalPort, GetCachedHostName(connection.LocalAddress), searchText),
                                    BuildEndpointBlock("Remote", connection.RemoteDisplayAddress, connection.RemotePort, GetCachedHostName(connection.RemoteAddress), searchText)))));
}

Element BuildEndpointBlock(string label, string address, int port, string? hostName, string searchText)
{
    var normalizedFilter = NormalizePortFilter(searchText);
    var addressText = new TextBlock()
        .Text(address)
        .FontSize(11);
    var hostText = new TextBlock()
        .Text(hostName ?? string.Empty)
        .FontSize(11);
    var portText = new TextBlock()
        .Text(port.ToString(CultureInfo.InvariantCulture))
        .FontSize(12)
        .Bold();
    var addressMatches = MatchesAnyText(normalizedFilter, address);
    var hostMatches = MatchesAnyText(normalizedFilter, hostName);
    var portMatches = MatchesAnyText(normalizedFilter, port.ToString(CultureInfo.InvariantCulture));

    if (addressMatches)
    {
        addressText.Foreground(portHighlightColor);
    }

    if (hostMatches)
    {
        hostText.Foreground(portHighlightColor);
    }

    if (portMatches)
    {
        portText.Foreground(portHighlightColor);
    }

    return new StackPanel()
        .Vertical()
        .Spacing(2)
        .WithTheme((theme, stack) =>
        {
            var mutedText = theme.Palette.WindowText.Lerp(theme.Palette.WindowBackground, 0.42);
            if (!addressMatches)
            {
                addressText.Foreground(mutedText);
            }

            if (!hostMatches)
            {
                hostText.Foreground(mutedText);
            }
        })
        .Children(
            new StackPanel()
                .Horizontal()
                .Spacing(6)
                .Children(
                    new TextBlock()
                        .Text(label)
                        .FontSize(11),
                    addressText,
                    portText),
            hostText);
}

Element BuildConnectionActionArea(TcpConnectionInfo connection)
{
    var area = new StackPanel()
        .Vertical()
        .Spacing(6)
        .CenterVertical()
        .Width(92);

    if (connection.CanTerminate)
    {
        area.Children(
            new Button()
                .Content("Close")
                .OnClick(() => CloseConnection(connection)),
            new Button()
                .Content("Kill svc")
                .OnClick(() => KillConnectionProcess(connection)));
    }
    else
    {
        area.Children(
            new Button()
                .Content("Close")
                .OnClick(() => CloseConnection(connection)),
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

async void OnSearchTextChanged(string text)
{
    portFilterText.Value = text;
    var requestVersion = ++searchUpdateVersion;

    await Task.Delay(160);
    if (requestVersion == searchUpdateVersion)
    {
        UpdateSnapshotView();
    }
}

async void RefreshSnapshot()
{
    await RefreshViewAsync(activeView);
}

async Task RefreshViewAsync(ViewMode requestedView)
{
    if (refreshInProgress)
    {
        statusText.Value = "Refresh already running...";
        return;
    }

    if (DateTime.UtcNow - lastRefreshStarted < TimeSpan.FromMilliseconds(700))
    {
        return;
    }

    refreshInProgress = true;
    lastRefreshStarted = DateTime.UtcNow;
    var requestVersion = ++refreshVersion;
    try
    {
        if (requestedView == ViewMode.Ports)
        {
            statusText.Value = "Refreshing ports...";
            var refreshedSnapshot = await Task.Run(CaptureSnapshot);
            if (requestVersion != refreshVersion || activeView != requestedView)
            {
                return;
            }

            currentSnapshot = refreshedSnapshot;
            statusText.Value = currentSnapshot.Status;
        }
        else
        {
            statusText.Value = "Refreshing connections...";
            var refreshedSnapshot = await Task.Run(CaptureConnectionSnapshot);
            if (requestVersion != refreshVersion || activeView != requestedView)
            {
                return;
            }

            currentConnectionSnapshot = refreshedSnapshot;
            connectionsLoaded = true;
            statusText.Value = currentConnectionSnapshot.Status;
            QueueHostNameLookups(currentConnectionSnapshot.Connections);
        }

        UpdateSnapshotView();
    }
    finally
    {
        refreshInProgress = false;
    }
}

async void SwitchView(ViewMode view)
{
    activeView = view;
    if (activeView == ViewMode.Connections && !connectionsLoaded)
    {
        listHost.Content = BuildInfoCard("Scanning connections", "Reading active TCP connections...");
        await RefreshViewAsync(ViewMode.Connections);
    }

    statusText.Value = activeView == ViewMode.Ports
        ? currentSnapshot.Status
        : currentConnectionSnapshot.Status;
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

async void KillConnectionProcess(TcpConnectionInfo connection)
{
    var confirmation = MessageBox.Show(
        window.Handle,
        $"Kill {connection.DisplayName}?\n\nThis will terminate the service that owns this connection.",
        "portsnuffer",
        MessageBoxButtons.YesNo,
        MessageBoxIcon.Warning);

    if (confirmation != MessageBoxResult.Yes)
    {
        return;
    }

    try
    {
        await Task.Run(() =>
        {
            using var process = Process.GetProcessById(connection.ProcessId);
            process.Kill();
            process.WaitForExit(2000);
        });

        statusText.Value = $"Terminated {connection.DisplayName} at {DateTime.Now:HH:mm:ss}.";
        currentConnectionSnapshot = await Task.Run(CaptureConnectionSnapshot);
        connectionsLoaded = true;
        QueueHostNameLookups(currentConnectionSnapshot.Connections);
        UpdateSnapshotView();
    }
    catch (Exception ex)
    {
        statusText.Value = $"Failed to terminate {connection.DisplayName}: {ex.Message}";
        _ = MessageBox.Show(
            window.Handle,
            ex.Message,
            "Unable to terminate service",
            MessageBoxButtons.Ok,
            MessageBoxIcon.Error);
        currentConnectionSnapshot = await Task.Run(CaptureConnectionSnapshot);
        connectionsLoaded = true;
        QueueHostNameLookups(currentConnectionSnapshot.Connections);
        UpdateSnapshotView();
    }
}

async void CloseConnection(TcpConnectionInfo connection)
{
    if (!connection.CanClose)
    {
        _ = MessageBox.Show(
            window.Handle,
            "Direct connection close is currently available for IPv4 TCP connections only.",
            "Unable to close connection",
            MessageBoxButtons.Ok,
            MessageBoxIcon.Information);
        return;
    }

    var confirmation = MessageBox.Show(
        window.Handle,
        $"Close this TCP connection?\n\n{connection.LocalEndpoint} -> {connection.RemoteEndpoint}",
        "portsnuffer",
        MessageBoxButtons.YesNo,
        MessageBoxIcon.Warning);

    if (confirmation != MessageBoxResult.Yes)
    {
        return;
    }

    try
    {
        await Task.Run(() => PortInventory.CloseConnection(connection));
        statusText.Value = $"Closed {connection.LocalEndpoint} -> {connection.RemoteEndpoint} at {DateTime.Now:HH:mm:ss}.";
        currentConnectionSnapshot = await Task.Run(CaptureConnectionSnapshot);
        connectionsLoaded = true;
        QueueHostNameLookups(currentConnectionSnapshot.Connections);
        UpdateSnapshotView();
    }
    catch (Exception ex)
    {
        statusText.Value = $"Failed to close connection: {ex.Message}";
        _ = MessageBox.Show(
            window.Handle,
            ex.Message,
            "Unable to close connection",
            MessageBoxButtons.Ok,
            MessageBoxIcon.Error);
        currentConnectionSnapshot = await Task.Run(CaptureConnectionSnapshot);
        connectionsLoaded = true;
        QueueHostNameLookups(currentConnectionSnapshot.Connections);
        UpdateSnapshotView();
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

ConnectionSnapshotState CaptureConnectionSnapshot()
{
    try
    {
        var connections = PortInventory.ConnectionsSnapshot();
        return new ConnectionSnapshotState(connections, null, BuildConnectionStatus(connections.Count));
    }
    catch (Exception ex)
    {
        return new ConnectionSnapshotState(
            Array.Empty<TcpConnectionInfo>(),
            ex.Message,
            $"Connection scan failed at {DateTime.Now:HH:mm:ss}.");
    }
}

string? GetCachedHostName(IPAddress address)
    => hostNameCache.TryGetValue(address, out var hostName) ? hostName : null;

void QueueHostNameLookups(IReadOnlyList<TcpConnectionInfo> connections)
{
    var lookupVersion = ++dnsVersion;
    foreach (var address in connections
                 .SelectMany(static connection => new[] { connection.LocalAddress, connection.RemoteAddress })
                 .Distinct()
                 .Where(ShouldResolveHostName))
    {
        if (hostNameCache.ContainsKey(address) || !hostNameLookupsInFlight.Add(address))
        {
            continue;
        }

        _ = ResolveHostNameAsync(address, lookupVersion);
    }
}

async Task ResolveHostNameAsync(IPAddress address, int lookupVersion)
{
    string? hostName = null;
    try
    {
        hostName = (await Dns.GetHostEntryAsync(address)).HostName;
    }
    catch
    {
    }

    hostNameCache[address] = hostName;
    hostNameLookupsInFlight.Remove(address);

    if (lookupVersion == dnsVersion)
    {
        QueueHostNameViewUpdate();
    }
}

void QueueHostNameViewUpdate()
{
    if (hostNameUpdateQueued)
    {
        return;
    }

    hostNameUpdateQueued = true;
    _ = ApplyHostNameViewUpdateAsync(dnsVersion);
}

async Task ApplyHostNameViewUpdateAsync(int updateVersion)
{
    await Task.Delay(750);
    hostNameUpdateQueued = false;

    if (updateVersion == dnsVersion && activeView == ViewMode.Connections && !refreshInProgress)
    {
        UpdateSnapshotView();
    }
}

bool ShouldResolveHostName(IPAddress address)
    => !IPAddress.Any.Equals(address)
        && !IPAddress.IPv6Any.Equals(address)
        && !IPAddress.Loopback.Equals(address)
        && !IPAddress.IPv6Loopback.Equals(address);

IconSource LoadAppIcon()
{
    using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("portsnuffer.ico");
    if (stream is null)
    {
        return IconSource.FromFile(Path.Combine(AppContext.BaseDirectory, "Assets", "portsnuffer.ico"));
    }

    using var memory = new MemoryStream();
    stream.CopyTo(memory);
    return IconSource.FromBytes(memory.ToArray());
}

void UpdateSnapshotView()
{
    var nextContent = activeView == ViewMode.Ports
        ? BuildSnapshotBody(currentSnapshot, portFilterText.Value)
        : BuildConnectionBody(currentConnectionSnapshot, portFilterText.Value);

    listHost.Content = new StackPanel();
    GC.Collect();
    GC.WaitForPendingFinalizers();

    listHost.Content = nextContent;
}

Element BuildPortBindings(IReadOnlyList<PortBinding> bindings, string portFilter)
{
    return new WrapPanel()
        .Spacing(6)
        .Children(bindings.Select(binding => BuildPortChip(binding, MatchesPortFilter(binding, portFilter))).ToArray());
}

Element BuildPortChip(PortBinding binding, bool isMatch)
{
    var protocolText = new TextBlock()
        .Text($"{(binding.Protocol == PortProtocol.Tcp ? "TCP" : "UDP")}{(binding.IsIpv6 ? "6" : string.Empty)}")
        .FontSize(11);
    var addressText = new TextBlock()
        .Text(binding.DisplayAddress)
        .FontSize(11);
    var separatorText = new TextBlock()
        .Text(":")
        .FontSize(11);
    var portText = new TextBlock()
        .Text(binding.Port.ToString(CultureInfo.InvariantCulture))
        .FontSize(11)
        .Bold();

    if (isMatch)
    {
        portText.Foreground(portHighlightColor);
    }

    return new Border()
        .Padding(7, 4)
        .CornerRadius(4)
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
                .WithTheme((theme, stack) =>
                {
                    var mutedText = theme.Palette.WindowText.Lerp(theme.Palette.WindowBackground, 0.42);
                    addressText.Foreground(mutedText);
                    separatorText.Foreground(mutedText);
                })
                .Children(
                    protocolText,
                    addressText,
                    separatorText,
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

IReadOnlyList<TcpConnectionInfo> FilterConnections(IReadOnlyList<TcpConnectionInfo> connections, string searchText)
{
    var normalizedFilter = NormalizePortFilter(searchText);
    if (normalizedFilter.Length == 0)
    {
        return connections;
    }

    return connections
        .Where(connection => MatchesConnectionFilter(connection, normalizedFilter))
        .ToArray();
}

bool MatchesPortFilter(PortBinding binding, string portFilter)
{
    var normalizedFilter = NormalizePortFilter(portFilter);
    return normalizedFilter.Length != 0
        && (binding.Port.ToString(CultureInfo.InvariantCulture).Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || binding.LocalAddress.ToString().Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || binding.DisplayEndpoint.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase));
}

bool MatchesConnectionFilter(TcpConnectionInfo connection, string searchText)
{
    var normalizedFilter = NormalizePortFilter(searchText);
    return normalizedFilter.Length != 0
        && (connection.ProcessName.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.ProcessId.ToString(CultureInfo.InvariantCulture).Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.Direction.ToString().Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.State.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.LocalPort.ToString(CultureInfo.InvariantCulture).Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.RemotePort.ToString(CultureInfo.InvariantCulture).Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.LocalAddress.ToString().Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.RemoteAddress.ToString().Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.LocalEndpoint.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || connection.RemoteEndpoint.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase)
            || (GetCachedHostName(connection.LocalAddress)?.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (GetCachedHostName(connection.RemoteAddress)?.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase) ?? false));
}

bool MatchesAnyText(string normalizedFilter, params string?[] values)
    => normalizedFilter.Length != 0
        && values.Any(value => value?.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase) ?? false);

string NormalizePortFilter(string portFilter)
    => portFilter.Trim();

string BuildStatus(int processCount)
{
    var timestamp = DateTime.Now.ToString("HH:mm:ss");
    return processCount == 0
        ? $"No listening TCP or bound UDP ports found at {timestamp}."
        : $"Found {processCount} process{(processCount == 1 ? string.Empty : "es")} with open ports at {timestamp}.";
}

string BuildConnectionStatus(int connectionCount)
{
    var timestamp = DateTime.Now.ToString("HH:mm:ss");
    return connectionCount == 0
        ? $"No active TCP connections found at {timestamp}."
        : $"Found {connectionCount} TCP connection{(connectionCount == 1 ? string.Empty : "s")} at {timestamp}.";
}

enum ViewMode
{
    Ports,
    Connections
}

readonly record struct SnapshotState(
    IReadOnlyList<PortProcessInfo> Processes,
    string? ErrorMessage,
    string Status);

readonly record struct ConnectionSnapshotState(
    IReadOnlyList<TcpConnectionInfo> Connections,
    string? ErrorMessage,
    string Status);
