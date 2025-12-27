#include <Windows.h>
#include <stdio.h>

BOOL NAC_IsSecureBootEnabled(void) {
	HKEY hkey = NULL;
	DWORD val = 0, sz = sizeof(val), type = 0;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS) {
		return FALSE;
	}
	LONG r = RegQueryValueExW(hkey, L"UEFISecureBootEnabled", NULL, &type, (LPBYTE)&val, &sz);
	RegCloseKey(hkey);
	if (r != ERROR_SUCCESS || type != REG_DWORD) return FALSE;
	return (val != 0);
}
