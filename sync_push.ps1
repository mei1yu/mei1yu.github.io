[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   ⚔️ Web安全知识库 - 一键同步并上传到 GitHub Pages" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$src = "D:\黑曜石ai笔记"
$dst = "D:\mei1yu.github.io\content"

Write-Host "[1/3] 正在同步本地最新修改到发布目录..." -ForegroundColor Yellow
robocopy $src $dst /E /XD .obsidian .git templates /XF *.log *.bak *.tmp *.bat *.ps1 > $null
Write-Host "[完成] 笔记同步完成！" -ForegroundColor Green
Write-Host ""

Set-Location "D:\mei1yu.github.io"

Write-Host "[2/3] 正在检查本地变更并提交..." -ForegroundColor Yellow
git add .
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    git commit -m "sync: update security notes"
    Write-Host "[完成] 已成功记录最新版本提交！" -ForegroundColor Green
} else {
    Write-Host "[提示] 内容已是最新，直接同步远程状态..." -ForegroundColor Gray
}
Write-Host ""

Write-Host "[3/3] 正在推送到 GitHub 远程仓库 (https://github.com/mei1yu/mei1yu.github.io)..." -ForegroundColor Yellow
Write-Host "(如果是首次连接，会自动唤起浏览器或凭据弹窗，请点击授权)" -ForegroundColor DarkGray
Write-Host ""

git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host " 🎉 恭喜！推送成功！" -ForegroundColor Green
    Write-Host " GitHub Actions 云端正在自动编译打包..." -ForegroundColor Green
    Write-Host " 稍等 1~2 分钟即可访问你的专属免费博客：" -ForegroundColor Green
    Write-Host " 👉 https://mei1yu.github.io/" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[错误] 推送遇到问题，请检查网络或 GitHub 授权。" -ForegroundColor Red
}

Write-Host ""
