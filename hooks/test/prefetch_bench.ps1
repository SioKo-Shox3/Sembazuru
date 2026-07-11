param(
    [switch]$SelfTest
)

# Parses and validates the ignored production-path prefetch benchmark.
$ErrorActionPreference = 'Stop'

$prefix = 'PREFETCH_BENCH '
$expectedProperties = @(
    'concurrency',
    'prefetch_p50_ms',
    'prefetch_p95_ms',
    'foreground_p50_ms',
    'foreground_p95_ms',
    'peak_tasks',
    'transfer_bytes'
)
$integerMetrics = @('concurrency', 'peak_tasks', 'transfer_bytes')
$latencyMetrics = @('prefetch_p50_ms', 'prefetch_p95_ms', 'foreground_p50_ms', 'foreground_p95_ms')
$expectedConcurrency = [decimal[]]@(8, 16, 32, 64)

function Get-PositiveIntegerToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Json,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $escapedName = [regex]::Escape($Name)
    # Benchmark rows are flat objects. The negative lookbehind prevents an
    # escaped property-looking string value from being counted as a real key.
    $pattern = '(?<!\\)"' + $escapedName + '"\s*:\s*(?<token>[^,}\s]+)'
    $matches = [regex]::Matches(
        $Json,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($matches.Count -ne 1) {
        throw "integer property $Name must appear exactly once, got $($matches.Count)"
    }

    $token = $matches[0].Groups['token'].Value
    if ($token -cnotmatch '^[1-9][0-9]*$') {
        throw "metric $Name must use a positive decimal integer JSON token, got '$token'"
    }

    $value = [decimal]0
    $parsed = [decimal]::TryParse(
        $token,
        [System.Globalization.NumberStyles]::None,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$value
    )
    if (-not $parsed -or $value -gt [decimal][uint64]::MaxValue) {
        throw "metric $Name is outside the u64 range: '$token'"
    }
    return $value
}

function ConvertFrom-PrefetchBenchRows {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RawRows
    )

    if ($RawRows.Count -ne 4) {
        throw "expected exactly 4 PREFETCH_BENCH rows, got $($RawRows.Count)"
    }

    $rows = @()
    foreach ($raw in $RawRows) {
        if (-not $raw.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw "invalid PREFETCH_BENCH prefix: $raw"
        }
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

        foreach ($name in $integerMetrics) {
            $row.$name = Get-PositiveIntegerToken -Json $json -Name $name
        }

        foreach ($name in $latencyMetrics) {
            $value = $row.$name
            if ($value -isnot [ValueType] -or $value -is [bool]) {
                $typeName = if ($null -eq $value) { 'null' } else { $value.GetType().FullName }
                throw "metric $name must be a numeric JSON value, got '$value' ($typeName)"
            }
            try {
                $number = [Convert]::ToDouble($value, [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                throw "metric $name must be convertible to a finite number, got '$value'"
            }
            if ($number -le 0 -or [double]::IsNaN($number) -or [double]::IsInfinity($number)) {
                throw "metric $name must be a finite positive number, got '$value'"
            }
        }

        if ($row.peak_tasks -gt $row.concurrency) {
            throw "peak_tasks $($row.peak_tasks) exceeds concurrency $($row.concurrency)"
        }
        $rows += $row
    }

    $actualConcurrency = [decimal[]]@($rows.concurrency | Sort-Object)
    if (@(Compare-Object $expectedConcurrency $actualConcurrency).Count -ne 0) {
        throw "unexpected concurrency set: $($actualConcurrency -join ',')"
    }
    $transferValues = [decimal[]]@($rows.transfer_bytes | Sort-Object -Unique)
    if ($transferValues.Count -ne 1) {
        throw "transfer_bytes differs by concurrency: $($transferValues -join ',')"
    }

    return $rows
}

function Assert-PrefetchRowsAccepted {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Rows
    )

    try {
        $parsed = @(ConvertFrom-PrefetchBenchRows -RawRows $Rows)
    } catch {
        throw "self-test '$Name' expected acceptance, got: $($_.Exception.Message)"
    }
    if ($parsed.Count -ne 4) {
        throw "self-test '$Name' expected 4 parsed rows, got $($parsed.Count)"
    }
}

function Assert-PrefetchRowsRejected {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Rows
    )

    try {
        $null = @(ConvertFrom-PrefetchBenchRows -RawRows $Rows)
    } catch {
        return
    }
    throw "self-test '$Name' expected rejection"
}

function Invoke-PrefetchBenchSelfTest {
    $validRows = @(
        'PREFETCH_BENCH {"concurrency":8,"prefetch_p50_ms":1.0,"prefetch_p95_ms":1.1,"foreground_p50_ms":1.2,"foreground_p95_ms":1.3,"peak_tasks":8,"transfer_bytes":33554432}',
        'PREFETCH_BENCH {"concurrency":16,"prefetch_p50_ms":1.0,"prefetch_p95_ms":1.1,"foreground_p50_ms":1.2,"foreground_p95_ms":1.3,"peak_tasks":16,"transfer_bytes":33554432}',
        'PREFETCH_BENCH {"concurrency":32,"prefetch_p50_ms":1.0,"prefetch_p95_ms":1.1,"foreground_p50_ms":1.2,"foreground_p95_ms":1.3,"peak_tasks":32,"transfer_bytes":33554432}',
        'PREFETCH_BENCH {"concurrency":64,"prefetch_p50_ms":1.0,"prefetch_p95_ms":1.1,"foreground_p50_ms":1.2,"foreground_p95_ms":1.3,"peak_tasks":64,"transfer_bytes":33554432}'
    )
    Assert-PrefetchRowsAccepted -Name 'valid rows' -Rows $validRows

    $case = @($validRows)
    $case[0] = $case[0].Replace('"concurrency":8', '"concurrency":8.0')
    Assert-PrefetchRowsRejected -Name 'integer encoded as 8.0' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"concurrency":8', '"concurrency":8.5')
    Assert-PrefetchRowsRejected -Name 'fractional integer' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"concurrency":8', '"concurrency":1e2')
    Assert-PrefetchRowsRejected -Name 'exponent integer' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace(',"transfer_bytes":33554432', '')
    Assert-PrefetchRowsRejected -Name 'missing property' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('}', ',"extra":1}')
    Assert-PrefetchRowsRejected -Name 'extra property' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"concurrency":8,', '"concurrency":8,"concurrency":8,')
    Assert-PrefetchRowsRejected -Name 'duplicate integer property' -Rows $case

    $propertyLookalike = '{"note":"\"concurrency\":999","concurrency":8}'
    $lookalikeValue = Get-PositiveIntegerToken -Json $propertyLookalike -Name 'concurrency'
    if ($lookalikeValue -ne [decimal]8) {
        throw "self-test 'escaped property lookalike' expected 8, got $lookalikeValue"
    }

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":1e309')
    Assert-PrefetchRowsRejected -Name 'infinite-equivalent latency' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"foreground_p50_ms":1.2', '"foreground_p50_ms":0')
    Assert-PrefetchRowsRejected -Name 'non-positive latency' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"peak_tasks":8', '"peak_tasks":0')
    Assert-PrefetchRowsRejected -Name 'zero integer' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"peak_tasks":8', '"peak_tasks":9')
    Assert-PrefetchRowsRejected -Name 'peak exceeds concurrency' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"concurrency":8', '"concurrency":9')
    Assert-PrefetchRowsRejected -Name 'unexpected concurrency set' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"transfer_bytes":33554432', '"transfer_bytes":33554431')
    Assert-PrefetchRowsRejected -Name 'transfer mismatch' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"transfer_bytes":33554432', '"transfer_bytes":18446744073709551616')
    Assert-PrefetchRowsRejected -Name 'integer exceeds u64' -Rows $case
}

if ($SelfTest) {
    Invoke-PrefetchBenchSelfTest
    Write-Output 'PREFETCH_BENCH_SELF_TEST PASS'
    exit 0
}

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

$rawRows = @($output | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
$null = @(ConvertFrom-PrefetchBenchRows -RawRows $rawRows)
$rawRows | Write-Output
