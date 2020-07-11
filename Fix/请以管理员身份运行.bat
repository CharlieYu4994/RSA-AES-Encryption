@echo 开始复制
cd /d %~dp0
copy pythoncom38.dll %windir%\system32\
copy pywintypes38.dll %windir%\system32\
@echo 复制结束
@pause