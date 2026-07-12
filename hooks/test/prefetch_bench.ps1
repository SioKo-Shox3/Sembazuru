param(
    [switch]$SelfTest
)

# Parses and validates the ignored production-path prefetch benchmark.
$ErrorActionPreference = 'Stop'

$prefix = 'PREFETCH_BENCH '
$jsonNumberToken = '-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?'
$canonicalRowPattern = (
    '\A\{"concurrency":(?<concurrency>[1-9][0-9]*),' +
    '"prefetch_p50_ms":(?<prefetch_p50_ms>' + $jsonNumberToken + '),' +
    '"prefetch_p95_ms":(?<prefetch_p95_ms>' + $jsonNumberToken + '),' +
    '"foreground_p50_ms":(?<foreground_p50_ms>' + $jsonNumberToken + '),' +
    '"foreground_p95_ms":(?<foreground_p95_ms>' + $jsonNumberToken + '),' +
    '"peak_tasks":(?<peak_tasks>[1-9][0-9]*),' +
    '"transfer_bytes":(?<transfer_bytes>[1-9][0-9]*)\}\z'
)
$expectedConcurrency = [decimal[]]@(8, 16, 32, 64)

function ConvertTo-U64Decimal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $value = [decimal]0
    $parsed = [decimal]::TryParse(
        $Token,
        [System.Globalization.NumberStyles]::None,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$value
    )
    if (-not $parsed -or $value -gt [decimal][uint64]::MaxValue) {
        throw "metric $Name is outside the u64 range: '$Token'"
    }
    return $value
}

function ConvertTo-PositiveFiniteDouble {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $value = [double]0
    $parsed = [double]::TryParse(
        $Token,
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$value
    )
    if (-not $parsed -or $value -le 0 -or [double]::IsNaN($value) -or [double]::IsInfinity($value)) {
        throw "metric $Name must be a finite positive JSON number, got '$Token'"
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
        $match = [regex]::Match(
            $json,
            $canonicalRowPattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $match.Success) {
            throw "PREFETCH_BENCH row does not match the canonical 7-property schema: $json"
        }

        $row = [pscustomobject][ordered]@{
            concurrency = ConvertTo-U64Decimal -Token $match.Groups['concurrency'].Value -Name 'concurrency'
            prefetch_p50_ms = ConvertTo-PositiveFiniteDouble -Token $match.Groups['prefetch_p50_ms'].Value -Name 'prefetch_p50_ms'
            prefetch_p95_ms = ConvertTo-PositiveFiniteDouble -Token $match.Groups['prefetch_p95_ms'].Value -Name 'prefetch_p95_ms'
            foreground_p50_ms = ConvertTo-PositiveFiniteDouble -Token $match.Groups['foreground_p50_ms'].Value -Name 'foreground_p50_ms'
            foreground_p95_ms = ConvertTo-PositiveFiniteDouble -Token $match.Groups['foreground_p95_ms'].Value -Name 'foreground_p95_ms'
            peak_tasks = ConvertTo-U64Decimal -Token $match.Groups['peak_tasks'].Value -Name 'peak_tasks'
            transfer_bytes = ConvertTo-U64Decimal -Token $match.Groups['transfer_bytes'].Value -Name 'transfer_bytes'
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

    $reviewCases = @()
    $case = @($validRows)
    $case[0] = $case[0].Replace('"concurrency":8,', '"concurrency":8,"\u0063oncurrency":9,')
    $reviewCases += [pscustomobject]@{ Name = 'unicode escaped semantic duplicate'; Rows = [string[]]$case }

    $case = @($validRows)
    $case[0] = $case[0].Replace(
        '"prefetch_p50_ms":1.0,',
        '"prefetch_p50_ms":1.0,"prefetch_p50_ms":2.0,'
    )
    $reviewCases += [pscustomobject]@{ Name = 'literal latency duplicate'; Rows = [string[]]$case }

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"PREFETCH_P50_MS":1.0')
    $reviewCases += [pscustomobject]@{ Name = 'case-only latency key'; Rows = [string[]]$case }

    $acceptedReviewCases = @()
    foreach ($reviewCase in $reviewCases) {
        try {
            $null = @(ConvertFrom-PrefetchBenchRows -RawRows $reviewCase.Rows)
            $acceptedReviewCases += $reviewCase.Name
        } catch {
            # Expected: every review regression case must be rejected.
        }
    }
    if ($acceptedReviewCases.Count -ne 0) {
        throw "self-test accepted invalid review rows: $($acceptedReviewCases -join ', ')"
    }

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

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":"\"concurrency\":999"')
    Assert-PrefetchRowsRejected -Name 'escaped property lookalike value' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":{"value":1.0}')
    Assert-PrefetchRowsRejected -Name 'nested latency value' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace(
        '{"concurrency":8,"prefetch_p50_ms":1.0,',
        '{"prefetch_p50_ms":1.0,"concurrency":8,'
    )
    Assert-PrefetchRowsRejected -Name 'reordered properties' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":1e2')
    Assert-PrefetchRowsAccepted -Name 'latency exponent JSON number' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":1e309')
    Assert-PrefetchRowsRejected -Name 'infinite-equivalent latency' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":Infinity')
    Assert-PrefetchRowsRejected -Name 'Infinity latency literal' -Rows $case

    $case = @($validRows)
    $case[0] = $case[0].Replace('"prefetch_p50_ms":1.0', '"prefetch_p50_ms":NaN')
    Assert-PrefetchRowsRejected -Name 'NaN latency literal' -Rows $case

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
