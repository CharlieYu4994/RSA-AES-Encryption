@echo 开始复制文件
cd /d %~dp0
copy pythoncom38.dll %windir%\system32\
copy pywintypes38.dll %windir%\system32\
@echo 复制完成
@pause