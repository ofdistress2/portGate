param(
    [string]$Dotnet = 'dotnet',
    [switch]$Publish,
    [switch]$SelfContained,
    [switch]$Package
)

$ErrorActionPreference = 'Stop'
if ($Package -and (-not $Publish -or -not $SelfContained)) {
    throw 'Для архива используйте -Publish -SelfContained -Package.'
}

$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_HOME = Join-Path $PSScriptRoot '.build-home'
$env:NUGET_PACKAGES = Join-Path $PSScriptRoot '.packages'

Push-Location $PSScriptRoot
try {
    & $Dotnet restore portGate.sln --configfile NuGet.Config
    if ($LASTEXITCODE) { throw 'Ошибка восстановления зависимостей.' }
    & $Dotnet build portGate.sln -c Release --no-restore -m:1
    if ($LASTEXITCODE) { throw 'Ошибка сборки.' }
    & $Dotnet run --project tests/portGate.Tests -c Release --no-build
    if ($LASTEXITCODE) { throw 'Тесты не пройдены.' }

    if ($Publish) {
        $mode = if ($SelfContained) { 'self-contained' } else { 'framework-dependent' }
        $standalone = if ($SelfContained) { 'true' } else { 'false' }
        $publishRoot = Join-Path $PSScriptRoot "publish/$mode"
        if (Test-Path -LiteralPath $publishRoot) {
            Remove-Item -LiteralPath $publishRoot -Recurse -Force
        }
        foreach ($component in @('Host', 'Manager')) {
            $project = "portGate.$component"
            & $Dotnet publish "src/$project/$project.csproj" -c Release -r win-x64 --self-contained $standalone -p:PublishSingleFile=false -o (Join-Path $publishRoot "portgate.$component") --configfile NuGet.Config
            if ($LASTEXITCODE) { throw 'Ошибка публикации.' }
        }

        $packageRoot = Join-Path $publishRoot 'portgate.Manager'
        Copy-Item "$publishRoot/portgate.Host/*" $packageRoot -Recurse -Force
        Copy-Item README.md,README.en.md,CONTRIBUTING.md,LICENSE,SECURITY.md $packageRoot -Force
        Copy-Item docs,licenses $packageRoot -Recurse -Force
        Get-ChildItem -LiteralPath $packageRoot -Filter '*.pdb' -File -Recurse | Remove-Item -Force

        $dependencyPackages = foreach ($assembly in @('portgate.Host', 'portgate.Manager')) {
            $dependencies = Get-Content -LiteralPath "$packageRoot/$assembly.deps.json" -Raw | ConvertFrom-Json
            foreach ($library in $dependencies.libraries.PSObject.Properties) {
                if ($library.Value.type -eq 'package') { $library.Value.path }
                if ($library.Value.type -eq 'runtimepack') {
                    $library.Name.Substring('runtimepack.'.Length).ToLowerInvariant()
                }
            }
        }
        foreach ($dependency in ($dependencyPackages | Sort-Object -Unique)) {
            $dependencyRoot = Join-Path $env:NUGET_PACKAGES $dependency
            $notices = Get-ChildItem -LiteralPath $dependencyRoot -File |
                Where-Object Name -Match '^(LICENSE|THIRD-?PARTY-?NOTICES)(\.txt)?$'
            if ($notices) {
                $noticeRoot = Join-Path "$packageRoot/licenses" $dependency
                New-Item -ItemType Directory -Path $noticeRoot -Force | Out-Null
                $notices | Copy-Item -Destination $noticeRoot
            }
        }

        $manifestEntries = @(Get-ChildItem -LiteralPath $packageRoot -File -Recurse |
            ForEach-Object { $_.FullName.Substring($packageRoot.Length + 1).Replace('\','/') } |
            Sort-Object)
        ConvertTo-Json -InputObject $manifestEntries | Set-Content "$packageRoot/package-manifest.json" -Encoding utf8

        if ($Package) {
            $version = ([xml](Get-Content Directory.Build.props -Raw)).Project.PropertyGroup.Version
            $archive = Join-Path $PSScriptRoot "publish/portGate-Windows-x64-$version.zip"
            Compress-Archive -Path "$packageRoot/*" -DestinationPath $archive -Force
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
            "$hash  $([IO.Path]::GetFileName($archive))" | Set-Content "$archive.sha256" -Encoding ascii
        }
    }
} finally { Pop-Location }
