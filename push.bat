@echo off
chcp 65001
set /p msg=Message: 
if [%msg%]==[] set msg=Update
git add -A
git commit -a -m "%msg%"
git push
pause