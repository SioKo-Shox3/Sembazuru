# Verifies the M0 "Done when": an injected DLL hooks one CreateFileW issued
# by cl.exe and logs it. Requires cl.exe on PATH (run from a VS dev shell or
# after msvc-dev-cmd in CI).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release')
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$interceptor = Join-Path $BuildDir 'interceptor.dll'
foreach ($f in @($launcher, $interceptor)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("sembazuru-poc-" + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
try {
    Push-Location $work
    'int main(void) { return 0; }' | Set-Content hello.c -Encoding ascii
    $env:SEMBAZURU_POC_LOG = Join-Path $work 'poc.log'

    & $launcher $interceptor cl /nologo /c hello.c
    if ($LASTEXITCODE -ne 0) { throw "launcher/cl.exe failed with exit code $LASTEXITCODE" }

    $hit = Select-String -Path $env:SEMBAZURU_POC_LOG -Pattern 'CreateFileW: .*hello\.c' |
        Select-Object -First 1
    if (-not $hit) {
        Write-Host '--- log head ---'
        Get-Content $env:SEMBAZURU_POC_LOG -TotalCount 20
        throw 'no CreateFileW(hello.c) line in the hook log'
    }
    $total = (Get-Content $env:SEMBAZURU_POC_LOG | Measure-Object -Line).Lines
    Write-Host "SMOKE PASS ($total CreateFileW calls logged from cl.exe)"
    Write-Host "evidence: $($hit.Line)"
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
