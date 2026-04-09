param(
    [string]$ProfilesDir = "src/STATIC_proxy/profiles",
    [string]$ManifestPath = "src/STATIC_proxy/profiles/manifest.json"
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$profilesPath = Resolve-Path (Join-Path $repoRoot $ProfilesDir)
$manifestFullPath = Join-Path $repoRoot $ManifestPath
$repoRootPath = $repoRoot.ProviderPath.TrimEnd('\\')

$profileEntries = Get-ChildItem -Path $profilesPath -Filter *.json |
    Where-Object { $_.Name -ne "manifest.json" } |
    Sort-Object Name |
    ForEach-Object {
        $relativePath = $_.FullName.Substring($repoRootPath.Length).TrimStart('\\').Replace("\", "/")
        [ordered]@{
            file_name = $_.Name
            path = $relativePath
            sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

$manifest = [ordered]@{
    profiles = @($profileEntries)
}

$json = ($manifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestFullPath, $json, $utf8NoBom)
Write-Host "Updated $ManifestPath with $($profileEntries.Count) profile hash(es)."