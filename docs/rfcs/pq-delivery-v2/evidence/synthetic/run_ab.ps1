param(
  [string]$UnitTests = "..\e2e-build\tests\Release\unit_tests.exe",
  [string]$Output = ".\raw\ab-genesis-sync-4096-v2-outputs-release-rerun.txt",
  [uint32]$Transactions = 64,
  [uint32]$OutputsPerTransaction = 64,
  [uint32]$Warmups = 2,
  [uint32]$Samples = 21
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$binaryPath = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot $UnitTests))
$outputPath = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot $Output))
$outputDirectory = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
  throw "UnitTests executable not found: $binaryPath"
}

$env:PQ_SYNC_BENCH_TXS = [string]$Transactions
$env:PQ_SYNC_BENCH_OUTPUTS_PER_TX = [string]$OutputsPerTransaction
$env:PQ_SYNC_BENCH_WARMUPS = [string]$Warmups
$env:PQ_SYNC_BENCH_SAMPLES = [string]$Samples

& $binaryPath `
  --gtest_filter=WalletLegacyBenchmark.DISABLED_GenesisSyncLegacyWindow64Vs1 `
  --gtest_also_run_disabled_tests `
  --gtest_color=no 2>&1 | Tee-Object -FilePath $outputPath

exit $LASTEXITCODE
