# 로컬 SBOM 생성 + grype 취약점 점검 (Windows · Docker Desktop)
#
# CI(.github/workflows/sbom.yml)와 같은 일을 로컬에서 하고, 결과를 파일로 남긴다.
#   1) 소스 SBOM   : syft dir:   → sbom-source.cdx.json
#   2) 이미지 SBOM : web/src 빌드 → syft docker: → sbom-image.cdx.json
#   3) grype DB    : Docker 볼륨에 저장해 두고 매번 최신으로 갱신, 기준 시각 기록 → grype-db-status.txt
#   4) grype 검사  : 이미지 SBOM → grype-image.json (수십 MB, 레포에 올리지 않음)
#   5) 요약        : summarize_grype.py → summary.md (레포에 올리는 것)
#
# 사용 예:
#   powershell -ExecutionPolicy Bypass -File docs\sbom\scripts\local_sbom_scan.ps1
#   powershell -ExecutionPolicy Bypass -File docs\sbom\scripts\local_sbom_scan.ps1 -Repo D:\team_one -OutDir D:\sbom_out
#
# 주의: 구버전 grype는 갱신이 멈춘 DB를 써서 취약점 수가 적게 나온다 (2026-10-29 실제 경험).
#       버전은 아래 기본값처럼 고정하고, 결과에는 반드시 DB 기준 시각을 함께 적는다.

param(
    [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path,
    [string]$OutDir = (Join-Path $PSScriptRoot ("..\results\" + (Get-Date -Format "yyyy-MM-dd"))),
    [string]$SyftImage = "anchore/syft:v1.18.1",
    [string]$GrypeImage = "anchore/grype:v0.121.0",
    [string]$DbVolume = "grype-db",
    [string]$WebImageTag = "shop-web:sbomtest"
)

$ErrorActionPreference = "Stop"

function Invoke-Docker {
    param([string[]]$DockerArgs)
    & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "docker $($DockerArgs -join ' ') 실패 (exit $LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Out = (Resolve-Path $OutDir).Path
Write-Host "레포   : $Repo"
Write-Host "결과   : $Out"

# 1) 소스 SBOM — 결과 파일은 컨테이너 안에서 직접 쓴다 (PowerShell 5.1의 > 는 UTF-16으로 저장해 JSON이 깨짐)
Write-Host "`n[1/5] 소스 SBOM"
Invoke-Docker @("run", "--rm", "-v", "${Repo}:/repo:ro", "-v", "${Out}:/out", $SyftImage,
    "dir:/repo", "-q", "-o", "cyclonedx-json=/out/sbom-source.cdx.json")

# 2) 이미지 SBOM — 실제 배포물과 같은 Dockerfile로 빌드
Write-Host "`n[2/5] 웹 이미지 빌드 + 이미지 SBOM"
Invoke-Docker @("build", "-t", $WebImageTag, (Join-Path $Repo "web\src"))
Invoke-Docker @("run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", "${Out}:/out", $SyftImage,
    "docker:$WebImageTag", "-q", "-o", "cyclonedx-json=/out/sbom-image.cdx.json")

# 3) grype DB — 볼륨에 저장해 재사용, 검사 전에 갱신하고 기준 시각을 남긴다
Write-Host "`n[3/5] grype DB 갱신"
& docker volume inspect $DbVolume *> $null
if ($LASTEXITCODE -ne 0) { Invoke-Docker @("volume", "create", $DbVolume) | Out-Null }
$GrypeBase = @("run", "--rm", "-e", "GRYPE_DB_CACHE_DIR=/grype-db", "-v", "${DbVolume}:/grype-db", "-v", "${Out}:/out", $GrypeImage)
Invoke-Docker ($GrypeBase + @("db", "update"))
$status = & docker @($GrypeBase + @("db", "status"))
if ($LASTEXITCODE -ne 0) { throw "grype db status 실패" }
$status | Set-Content -Encoding UTF8 (Join-Path $Out "grype-db-status.txt")
$status | Write-Host

# 4) grype 검사 — 전체 결과는 JSON으로 (보고서 원재료)
Write-Host "`n[4/5] grype 검사"
Invoke-Docker ($GrypeBase + @("sbom:/out/sbom-image.cdx.json", "-q", "-o", "json", "--file", "/out/grype-image.json"))

# 5) 요약
Write-Host "`n[5/5] 요약"
& python (Join-Path $PSScriptRoot "summarize_grype.py") (Join-Path $Out "grype-image.json") `
    --sbom (Join-Path $Out "sbom-image.cdx.json") -o (Join-Path $Out "summary.md")
if ($LASTEXITCODE -ne 0) { throw "summarize_grype.py 실패" }

Write-Host "`n완료: $Out"
Get-ChildItem $Out | Select-Object Name, Length | Format-Table -AutoSize
