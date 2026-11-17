# NetScope 环境准备脚本（Windows / PowerShell）
# 用法：右键“使用 PowerShell 运行”，或在项目根目录执行：
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $root

Write-Host "== 1/3 检查 Python ==" -ForegroundColor Cyan
$python = "python"
try {
    $version = & $python --version 2>&1
} catch {
    Write-Host "未找到 python，请先安装 Python 3.9+ 并加入 PATH。" -ForegroundColor Red
    exit 1
}
Write-Host "  使用 $version"

Write-Host "== 2/3 安装依赖 ==" -ForegroundColor Cyan
& $python -m pip install --upgrade pip | Out-Null
& $python -m pip install -r requirements.txt

Write-Host "== 3/3 检查 Npcap ==" -ForegroundColor Cyan
$wpcap = "C:\Windows\System32\Npcap\wpcap.dll"
$legacy = "C:\Windows\System32\wpcap.dll"
$service = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  Npcap 驱动已安装（服务状态：$($service.Status)）" -ForegroundColor Green
} elseif (Test-Path $wpcap) {
    Write-Host "  检测到 Npcap 文件，但服务未运行，请以管理员身份重新安装 Npcap。" -ForegroundColor Yellow
} else {
    Write-Host "  未检测到 Npcap。实时抓包必须安装：https://npcap.com" -ForegroundColor Yellow
    Write-Host "  安装时务必勾选：Install Npcap in WinPcap API-compatible Mode" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "完成。运行方式：run.bat  或  python main.py" -ForegroundColor Green
