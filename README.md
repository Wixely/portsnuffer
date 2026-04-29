# portsnuffer

`portsnuffer` is a small Windows desktop app that shows listening TCP ports and bound UDP ports grouped by process.

## Features

- Groups open ports by app/process
- Live port search with partial matching
- Highlights matching ports in orange
- Lets you terminate non-protected processes
- Launches with admin permissions so port/process access works reliably

## Run locally

```powershell
dotnet run
```

Windows should prompt for elevation when the app launches.

## Build

```powershell
dotnet publish .\portsnuffer.csproj -c Release
```

That produces a standalone 64-bit Native AOT executable.
