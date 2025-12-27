#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "nacflags.h"

typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, PLONG);
#define ThreadQuerySetWin32StartAddress 9
typedef struct MODRANGE { BYTE* base; SIZE_T size; } MODRANGE;

static int NAC_BuildModuleRanges(MODRANGE* out, int max) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	if (snap == INVALID_HANDLE_VALUE) return 0;
	MODULEENTRY32W me;
	me.dwSize = sizeof(me);
	int count = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (count >= max) break;
            out[count].base = (BYTE*)me.modBaseAddr;
            out[count].size = (SIZE_T)me.modBaseSize;
            count++;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return count;
}

static BOOL NAC_AddrInAnyModule(void* addr, MODRANGE* mods, int n)
{
    BYTE* a = (BYTE*)addr;
    for (int i = 0; i < n; i++) {
        BYTE* b = mods[i].base;
        BYTE* e = b + mods[i].size;
        if (a >= b && a < e) return TRUE;
    }
    return FALSE;
}

void NAC_ScanSuspiciousThreads(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    NtQueryInformationThread_t NtQueryInformationThread =
        (NtQueryInformationThread_t)GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!NtQueryInformationThread) return;
    MODRANGE mods[512];
    int modcount = NAC_BuildModuleRanges(mods, 512);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    if (!Thread32First(snap, &te)) { CloseHandle(snap); return; }
    do {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
        if (!th) continue;
        void* start = NULL;
        NTSTATUS st = NtQueryInformationThread(th, ThreadQuerySetWin32StartAddress,
            &start, sizeof(start), NULL);
        if (st == 0 && start != NULL) {
            if (!NAC_AddrInAnyModule(start, mods, modcount)) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(start, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    BOOL isPrivate = (mbi.Type == MEM_PRIVATE);
                    BOOL isExec = (mbi.State == MEM_COMMIT) && ((mbi.Protect & 0xFF) == PAGE_EXECUTE ||
                        (mbi.Protect & 0xFF) == PAGE_EXECUTE_READ ||
                        (mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE ||
                        (mbi.Protect & 0xFF) == PAGE_EXECUTE_WRITECOPY);
                    if (isPrivate && isExec) {
                        char msg[260];
                        snprintf(msg, sizeof(msg), "Thread %lu start=%p MEM_PRIVATE EXEC", te.th32ThreadID, start);
                        NAC_AddFlag(FLAG_SUSP_THREAD_START, 3, msg);
                        CloseHandle(th);
                        break; 
                    }
                }
            }
        }
        CloseHandle(th);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
}