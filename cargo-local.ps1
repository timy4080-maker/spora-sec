param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs)
$ErrorActionPreference = 'Stop'
$taskProtoc = Join-Path $env:USERPROFILE '.codex\tools\spora\protoc-36.2\bin\protoc.exe'
if (Test-Path -LiteralPath $taskProtoc) { $env:PROTOC = $taskProtoc }
$taskCargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$taskMingwBin = Join-Path $env:USERPROFILE '.codex\tools\spora\llvm-mingw-20261104-ucrt-x86_64\bin'
if (Test-Path -LiteralPath $taskMingwBin) {
    $env:PATH = "$taskMingwBin;$taskCargoBin;$env:PATH"
    $env:CC = 'clang'
    $env:AR = 'llvm-ar'
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER = 'clang'
    & cargo +1.100.0-x86_64-pc-windows-gnullvm @CargoArgs
} else {
    $env:PATH = "$taskCargoBin;$env:PATH"
    & cargo @CargoArgs
}
exit $LASTEXITCODE
