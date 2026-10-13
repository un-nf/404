param(
    [string]$ProfilesDir = "src/STATIC_proxy/profiles",
    [string]$ManifestPath = "src/STATIC_proxy/profiles/manifest.json"
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$profilesPath = Resolve-Path (Join-Path $repoRoot $ProfilesDir)
$manifestFullPath = Join-Path $repoRoot $ManifestPath
$repoRootPath = $repoRoot.ProviderPath.TrimEnd('\\')

$profileEntries = Get-ChildItem -Path $profilesPath -Filter *.json -Recurse |
    Where-Object { $_.Name -ne "manifest.json" } |
    Sort-Object FullName |
    ForEach-Object {
        # Profiles are published as UTF-8 without BOM, LF (see .gitattributes).
        # Normalize the file itself, not just the bytes passed to the hash.
        $profileText = [System.IO.File]::ReadAllText($_.FullName).Replace("`r`n", "`n").Replace("`r", "`n")
        $profileUtf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($_.FullName, $profileText, $profileUtf8)
        $relativePath = $_.FullName.Substring($repoRootPath.Length).TrimStart('\\').Replace("\", "/")
        $relativeProfilePath = $_.FullName.Substring($profilesPath.ProviderPath.Length).TrimStart('\\').Replace("\", "/")
        [ordered]@{
            file_name = $relativeProfilePath
            path = $relativePath
            sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

$manifest = [ordered]@{
    profiles = @($profileEntries)
}

$json = (($manifest | ConvertTo-Json -Depth 4).Replace("`r`n", "`n")) + "`n"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestFullPath, $json, $utf8NoBom)
Write-Host "Updated $ManifestPath with $($profileEntries.Count) profile hash(es)."
