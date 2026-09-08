param([string]$CoreSource, [string]$CoreBuild)
$ErrorActionPreference = 'Stop'
if (-not $CoreSource) { $CoreSource = Join-Path $PSScriptRoot '..\legacy-window\core-src' }
if (-not $CoreBuild) { $CoreBuild = Join-Path $PSScriptRoot '..\legacy-window\core-build-vs' }
$CoreSource = (Resolve-Path -LiteralPath $CoreSource).Path.Replace('\', '/')
$CoreBuild = (Resolve-Path -LiteralPath $CoreBuild).Path.Replace('\', '/')
$reviewBuild = Join-Path $PSScriptRoot 'build'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsInstall = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw 'Visual Studio C++ Build Tools not found' }
& (Join-Path $vsInstall 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
& cmake -S $PSScriptRoot -B $reviewBuild -G 'Ninja Multi-Config' "-DCORE_SRC=$CoreSource" "-DCORE_BUILD=$CoreBuild"
if ($LASTEXITCODE) { throw 'Configure failed' }
& cmake --build $reviewBuild --config Release --parallel 2
if ($LASTEXITCODE) { throw 'Build failed' }
& ctest --test-dir $reviewBuild -C Release --output-on-failure --output-log (Join-Path $reviewBuild 'ctest.log')
if ($LASTEXITCODE) { throw 'Tests failed' }
