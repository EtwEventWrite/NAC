#include <Windows.h>
#include <stdio.h>
#include "nacflags.h"

#define MAX_SEEN 512
static void* g_seen[MAX_SEEN];
static int g_seenCount = 0;

static BOOL SeenBase(void* base) {
    for (int i = 0; i < g_seenCount; i++) {
        if (g_seen[i] == base) return TRUE;
    }
    if (g_seenCount < MAX_SEEN) {
        g_seen[g_seenCount++] = base;
    }
    else {
        g_seen[(GetTickCount() / 1000) % MAX_SEEN] = base;
    }
    return FALSE;
}

static DWORD g_lastFlagTick = 0;
static BOOL CooldownOK(DWORD ms) {
    DWORD now = GetTickCount();
    if (now - g_lastFlagTick < ms) return FALSE;
    g_lastFlagTick = now;
    return TRUE;
}

static BOOL NAC_IsExecProtect(DWORD p) {
	p &= 0xFF;
	return (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
}

static BOOL NAC_IsRWX(DWORD p) {
	p &= 0xFF;
	return (p == PAGE_EXECUTE_READWRITE);
}

static BOOL NAC_LooksLikePE(void* base) {
	__try {
		unsigned char* b = (unsigned char*)base;
		if (b[0] != 'M' || b[1] != 'Z') return FALSE;
		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
		if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) return FALSE;
		DWORD pe = *(DWORD*)((unsigned char*)base + dos->e_lfanew);
		return (pe == 0x00004550);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

BOOL NAC_ScanPrivateExecMemory(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    unsigned char* p = (unsigned char*)si.lpMinimumApplicationAddress;
    unsigned char* end = (unsigned char*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    BOOL flagged = FALSE;
    while (p < end) {
        SIZE_T n = VirtualQuery(p, &mbi, sizeof(mbi));
        if (n == 0) break;
        DWORD prot = mbi.Protect;
        BOOL guarded = (prot & PAGE_GUARD) != 0;
        BOOL noaccess = (prot & PAGE_NOACCESS) != 0;
        if (mbi.State == MEM_COMMIT && !guarded && !noaccess) {
            if (mbi.Type == MEM_PRIVATE && NAC_IsExecProtect(prot)) {
                if (SeenBase(mbi.BaseAddress)) {
                    p += mbi.RegionSize;
                    continue;
                }
                BOOL rwx = NAC_IsRWX(prot);
                BOOL pe = FALSE;
                if (!rwx) pe = NAC_LooksLikePE(mbi.BaseAddress);
                if (!rwx && !pe) {
                    p += mbi.RegionSize;
                    continue;
                }
                if (!CooldownOK(10000)) { 
                    p += mbi.RegionSize;
                    continue;
                }
                char msg[260];
                snprintf(msg, sizeof(msg), "MEM_PRIVATE EXEC base=%p size=0x%Ix pe=%d prot=0x%lx", mbi.BaseAddress, (SIZE_T)mbi.RegionSize, pe ? 1 : 0, prot);
                if (rwx) {
                    NAC_AddFlag(FLAG_RWX_REGION, 3, msg);
                    flagged = TRUE;
                }
                if (pe) {
                    NAC_AddFlag(FLAG_PRIVATE_EXEC_REGION, 3, msg);
                    flagged = TRUE;
                }
                break;
            }
        }
        p += mbi.RegionSize;
    }
    return flagged;
}