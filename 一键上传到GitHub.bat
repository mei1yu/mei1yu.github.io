@echo off
title Syncing and Uploading to GitHub Pages...
echo ========================================================
echo    Web Security Knowledge Base - GitHub Pages Sync
echo ========================================================
echo.

echo [1/2] Syncing latest notes from Obsidian to deployment directory...
robocopy "D:\黑曜石ai笔记" "D:\mei1yu.github.io\content" /E /XD .obsidian .git templates /XF *.log *.bak *.tmp *.bat *.ps1 >nul
echo [OK] Notes sync complete.
echo.

echo [2/2] Pushing changes to GitHub: https://github.com/mei1yu/mei1yu.github.io ...
echo (If prompted, please click 'Sign in with your browser' to authorize)
echo.

cd /d "D:\mei1yu.github.io"
git add .
git commit -m "sync: update security notes" >nul 2>&1
git push -u origin main

echo.
echo ========================================================
if %ERRORLEVEL% EQU 0 (
    echo  [SUCCESS] All files pushed to GitHub!
    echo  GitHub Actions is now automatically building your blog.
    echo  Visit your blog at: https://mei1yu.github.io/
) else (
    echo  [ERROR] Git push failed. Please check network or GitHub login.
)
echo ========================================================
echo.
pause
