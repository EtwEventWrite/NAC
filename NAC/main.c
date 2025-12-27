#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR);
LoadLibraryW_t OriginalLoadLibraryW = NULL;

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
LoadLibraryA_t OriginalLoadLibraryA = NULL;

typedef HMODULE(WINAPI* LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
LoadLibraryExW_t OriginalLoadLibraryExW = NULL;

volatile BOOL SafePointReached = FALSE;

DWORD WINAPI SafePointThread(LPVOID lpParam) {
	printf("[safepoint] waiting for UnityPlayer + mono...\n");

	while (!GetModuleHandleA("UnityPlayer.dll")) Sleep(250);
	while (!GetModuleHandleA("mono-2.0-bdwgc.dll")) Sleep(250);

	printf("[safepoint] mono detected\n");
	Sleep(5000);

	SafePointReached = TRUE;
	printf("[safepoint] safe point reached late dll loads will now be blocked\n");
	return 0;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
	printf("[debug] LoadLibraryA called: %s\n", lpLibFileName);
	if (SafePointReached) {
		printf("[blocked] late dll load detected (A)\n");
		MessageBoxW(NULL, L"NAC | Detection", L"Gorilla Tag", MB_OK);
		ExitProcess(0);
	}
	return OriginalLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
	wprintf(L"[debug] LoadLibraryW called: %ls\n", lpLibFileName);
	if (SafePointReached) {
		wprintf(L"[blocked] late dll load detected\n");
		MessageBoxW(NULL, L"NAC | Detection", L"Gorilla Tag", MB_OK);
		ExitProcess(0);
	}
	return OriginalLoadLibraryW(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
	wprintf(L"[debug] LoadLibraryExW: %ls\n", name);
	if (SafePointReached) {
		printf("[blocked] late DLL load detected (ExW)\n");
		MessageBoxW(NULL, L"NAC | Detection", L"Gorilla Tag", MB_OK);
		ExitProcess(0);
	}
	return OriginalLoadLibraryExW(name, file, flags);
}

DWORD WINAPI HookUnityPlayerThread(LPVOID lpParam) {
	printf("[debug] waiting for UnityPlayer.dll to hook\n");

	HMODULE unity = NULL;
	while (!(unity = GetModuleHandleA("UnityPlayer.dll"))) {
		Sleep(250);
	}
	printf("[debug] UnityPlayer.dll found, hooking imports\n");
	IAT_LoadLibraryExW(unity);
	IAT_LoadLibraryW(unity);
	IAT_LoadLibraryA(unity);
	printf("[debug] UnityPlayer.dll hooked\n");
	return 0;
}


PIMAGE_IMPORT_DESCRIPTOR GetImportTable(HMODULE module) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);
	DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!rva) return NULL;
	return (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)module + rva);
}

int IAT_LoadLibraryW(HMODULE module) {
	PIMAGE_IMPORT_DESCRIPTOR imports = GetImportTable(module);
	if (!imports) { printf("[error] no import table\n"); return 0; }
	for (; imports->Name; imports++) {
		char* dllname = (char*)((BYTE*)module + imports->Name);
		printf("[debug] import dll: %s\n", dllname);
		if (_stricmp(dllname, "kernel32.dll") != 0) continue;
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)module + imports->FirstThunk);
		PIMAGE_THUNK_DATA origthunk = (PIMAGE_THUNK_DATA)((BYTE*)module + imports->OriginalFirstThunk);
		for (; origthunk->u1.AddressOfData; origthunk++, thunk++) {
			if (origthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
			PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)module + origthunk->u1.AddressOfData);
			printf("[debug] import: %s\n", name->Name);
			if (strcmp((char*)name->Name, "LoadLibraryW") == 0) {
				DWORD old;
				VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
				OriginalLoadLibraryW = (LoadLibraryW_t)thunk->u1.Function;
				thunk->u1.Function = (ULONGLONG)HookedLoadLibraryW;
				VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
				printf("[debug] LoadLibraryW hooked\n");
				return 1;
			}
		}
	}
	printf("[error] LoadLibraryW not found\n");
	return 0;
}

int IAT_LoadLibraryA(HMODULE module) {
	PIMAGE_IMPORT_DESCRIPTOR imports = GetImportTable(module);
	if (!imports) return 0;
	for (; imports->Name; imports++) {
		char* dllname = (char*)((BYTE*)module + imports->Name);
		if (_stricmp(dllname, "kernel32.dll") != 0) continue;
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)module + imports->FirstThunk);
		PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE*)module + imports->OriginalFirstThunk);
		for (; orig->u1.AddressOfData; orig++, thunk++) {
			if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
			PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)module + orig->u1.AddressOfData);
			if (strcmp((char*)name->Name, "LoadLibraryA") == 0) {
				DWORD old;
				VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
				OriginalLoadLibraryA = (LoadLibraryA_t)thunk->u1.Function;
				thunk->u1.Function = (ULONGLONG)HookedLoadLibraryA;
				VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
				printf("[debug] LoadLibraryA hooked\n");
				return 1;
			}
		}
	}
	return 0;
}

int IAT_LoadLibraryExW(HMODULE module) {
	PIMAGE_IMPORT_DESCRIPTOR imports = GetImportTable(module);
	if (!imports) return 0;
	for (; imports->Name; imports++) {
		char* dllname = (char*)((BYTE*)module + imports->Name);
		if (_stricmp(dllname, "kernel32.dll") != 0) continue;
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)module + imports->FirstThunk);
		PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE*)module + imports->OriginalFirstThunk);
		if (!orig) orig = thunk;
		for (; orig->u1.AddressOfData; orig++, thunk++) {
			if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
			PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)module + orig->u1.AddressOfData);
			if (strcmp((char*)name->Name, "LoadLibraryExW") == 0) {
				DWORD old;
				VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old);

				OriginalLoadLibraryExW = (LoadLibraryExW_t)thunk->u1.Function;
				thunk->u1.Function = (ULONGLONG)HookedLoadLibraryExW;

				VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
				printf("[debug] LoadLibraryExW hooked\n");
				return 1;
			}
		}
	}
	return 0;
}

static void DumpModulesOnce(void) {
	DWORD pid = GetCurrentProcessId();
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE) {
		printf("[NAC] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
		return;
	}
	MODULEENTRY32W me;
	me.dwSize = sizeof(me);
	if (!Module32FirstW(snap, &me)) {
		printf("[NAC] Module32FirstW failed: %lu\n", GetLastError());
		CloseHandle(snap);
		return;
	}
	printf("[NAC] ---- Modules (filtered) ----\n");
	do {
		if (wcsstr(me.szModule, L"Unity") ||
			wcsstr(me.szModule, L"Game") ||
			wcsstr(me.szModule, L"mono") ||
			wcsstr(me.szModule, L"il2cpp") ||
			wcsstr(me.szModule, L"Assembly"))
		{
			wprintf(L"[NAC] %ls\n", me.szModule);
		}
	} while (Module32NextW(snap, &me));
	printf("[NAC] ----------------------------\n");
	CloseHandle(snap);
}

DWORD WINAPI DebugDumpThread(LPVOID lpParam) {
	Sleep(2000);
	DumpModulesOnce();
	return 0;
}

DWORD WINAPI LateLoadTestThread(LPVOID lpParam) {
	printf("[debug] late load test thread ready\n");
	while (!SafePointReached) Sleep(200);
	printf("[debug] safepoint is active. F8 to test AC\n");
	while (1) {
		if (GetAsyncKeyState(VK_F8) & 1) {
			printf("[debug] Calling LoadLibraryW\n");
			LoadLibraryW(L"Windows.Gaming.Input.dll");
			printf("[debug] LoadLibraryW returned\n");
		}
		Sleep(50);
	}
	return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinst);

		AllocConsole();
		SetConsoleOutputCP(CP_UTF8);
		FILE* f;
		freopen_s(&f, "CONOUT$", "w", stdout);

		printf("[debug] NAC loaded\n");

		HMODULE exe = GetModuleHandleW(NULL);
		IAT_LoadLibraryExW(hinst);
		IAT_LoadLibraryW(hinst);
		IAT_LoadLibraryA(hinst);

		CreateThread(NULL, 0, SafePointThread, NULL, 0, NULL);
		CreateThread(NULL, 0, HookUnityPlayerThread, NULL, 0, NULL);
		CreateThread(NULL, 0, LateLoadTestThread, NULL, 0, NULL);
	}
	return TRUE;
}
