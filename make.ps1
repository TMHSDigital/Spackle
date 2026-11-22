<#
.SYNOPSIS
    Spackle build targets for Windows PowerShell. Mirrors the Makefile.
.EXAMPLE
    .\make.ps1 build
    .\make.ps1 test
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('all', 'build', 'test', 'test-race', 'lint', 'fmt', 'tidy', 'bench', 'clean', 'help')]
    [string]$Target = 'help'
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$Pkg = 'github.com/TMHSDigital/spackle'

function Get-GitValue([string[]]$GitArgs, [string]$Fallback) {
    try {
        $value = & git @GitArgs 2>$null
        if ($LASTEXITCODE -eq 0 -and $value) { return $value.Trim() }
    } catch { }
    return $Fallback
}

function Invoke-Checked([string]$Exe, [string[]]$ExeArgs) {
    & $Exe @ExeArgs
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($ExeArgs -join ' ') failed with exit code $LASTEXITCODE" }
}

function Invoke-Build {
    $version = Get-GitValue @('describe', '--tags', '--dirty', '--always') 'dev'
    $commit = Get-GitValue @('rev-parse', '--short', 'HEAD') 'none'
    $ldflags = "-s -w -X $Pkg/internal/version.Version=$version -X $Pkg/internal/version.Commit=$commit"
    $env:CGO_ENABLED = '0'
    Invoke-Checked 'go' @('build', '-trimpath', '-ldflags', $ldflags, '-o', 'spackle.exe', './cmd/spackle')
}

function Invoke-Test {
    $env:CGO_ENABLED = '0'
    Invoke-Checked 'go' @('test', '-shuffle=on', './...')
}

function Invoke-TestRace {
    # The race detector needs cgo and a C compiler on PATH.
    $env:CGO_ENABLED = '1'
    Invoke-Checked 'go' @('test', '-race', '-shuffle=on', './...')
}

function Invoke-Lint {
    Invoke-Checked 'go' @('vet', './...')
    Invoke-Checked 'golangci-lint' @('run')
}

switch ($Target) {
    'all' { Invoke-Lint; Invoke-Test; Invoke-Build }
    'build' { Invoke-Build }
    'test' { Invoke-Test }
    'test-race' { Invoke-TestRace }
    'lint' { Invoke-Lint }
    'fmt' { Invoke-Checked 'gofmt' @('-s', '-w', 'cmd', 'internal') }
    'tidy' { Invoke-Checked 'go' @('mod', 'tidy') }
    'bench' {
        Invoke-Build
        Invoke-Checked '.\spackle.exe' @('bench', '--corpus', 'bench/corpus', '--out', 'bench/results')
    }
    'clean' {
        Invoke-Checked 'go' @('clean')
        foreach ($p in 'dist', 'spackle', 'spackle.exe', 'coverage.out') {
            if (Test-Path $p) { Remove-Item -Recurse -Force $p }
        }
    }
    'help' {
        @(
            'build      Build spackle.exe'
            'test       Run unit tests'
            'test-race  Run unit tests with the race detector (needs cgo)'
            'lint       go vet and golangci-lint'
            'fmt        gofmt -s'
            'tidy       go mod tidy'
            'bench      Run the benchmark corpus and write bench/results/<date>-<model>.json'
            'clean      Remove build output'
        ) | ForEach-Object { Write-Output $_ }
    }
}
