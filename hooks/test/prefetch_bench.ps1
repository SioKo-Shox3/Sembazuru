# Parses and validates the ignored production-path prefetch benchmark.
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = @(& cargo test -p sembazuru-worker prefetch_concurrency_benchmark --release -- --ignored --nocapture 2>&1 | ForEach-Object { "$_" })
    $cargoExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference
    if ($cargoExitCode -ne 0) {
        throw "prefetch benchmark test failed with exit code $cargoExitCode"
    }
} finally {
    $ErrorActionPreference = $savedErrorPreference
    Pop-Location
}

$prefix = 'PREFETCH_BENCH '
$rawRows = @($output | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
if ($rawRows.Count -ne 4) {
    throw "expected exactly 4 PREFETCH_BENCH rows, got $($rawRows.Count)"
}

$expectedProperties = @(
    'concurrency',
    'prefetch_p50_ms',
    'prefetch_p95_ms',
    'foreground_p50_ms',
    'foreground_p95_ms',
    'peak_tasks',
    'transfer_bytes'
)
$rows = @()
foreach ($raw in $rawRows) {
    $json = $raw.Substring($prefix.Length)
    try {
        $row = $json | ConvertFrom-Json
    } catch {
        throw "invalid PREFETCH_BENCH JSON: $json ($($_.Exception.Message))"
    }
    $properties = @($row.PSObject.Properties.Name | Sort-Object)
    $propertyDiff = @(Compare-Object ($expectedProperties | Sort-Object) $properties)
    if ($propertyDiff.Count -ne 0) {
        throw "unexpected PREFETCH_BENCH properties: $($properties -join ',')"
    }
    foreach ($name in $expectedProperties) {
        $value = $row.$name
        if ($value -isnot [ValueType] -or [double]$value -le 0 -or [double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value)) {
            throw "metric $name must be a finite positive number, got '$value'"
        }
    }
    if ([int64]$row.peak_tasks -gt [int64]$row.concurrency) {
        throw "peak_tasks $($row.peak_tasks) exceeds concurrency $($row.concurrency)"
    }
    $rows += $row
}

$expectedConcurrency = @(8, 16, 32, 64)
$actualConcurrency = @($rows.concurrency | ForEach-Object { [int]$_ } | Sort-Object)
if (@(Compare-Object $expectedConcurrency $actualConcurrency).Count -ne 0) {
    throw "unexpected concurrency set: $($actualConcurrency -join ',')"
}
$transferValues = @($rows.transfer_bytes | ForEach-Object { [int64]$_ } | Sort-Object -Unique)
if ($transferValues.Count -ne 1) {
    throw "transfer_bytes differs by concurrency: $($transferValues -join ',')"
}

$rawRows | Write-Output
