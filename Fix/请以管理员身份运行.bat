@echo ��ʼ�����ļ�
cd /d %~dp0
copy pythoncom38.dll %windir%\system32\
copy pywintypes38.dll %windir%\system32\
@echo �������
@pause