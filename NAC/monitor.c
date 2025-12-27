#include <Windows.h>
#include <stdio.h>
#include "nacflags.h"
#include "memscan.h"
#include "threadscan.h"
#include "secureboot.h"

DWORD WINAPI MonitorThread(LPVOID lpParam)
{
    printf("[monitor] started\n");
    while (1) {
        NAC_DecayScore();
        if (!NAC_IsSecureBootEnabled()) {
            NAC_AddFlag(FLAG_SECUREBOOT_OFF, 1, "SecureBoot=OFF");
        }
        NAC_ScanPrivateExecMemory();
        NAC_ScanSuspiciousThreads();
        LONG score = NAC_GetScore();
        if (score >= 5) {
            printf("[action] score=%ld threshold reached -> closing\n", score);
            MessageBoxW(NULL, L"NAC | Multiple risk flags detected", L"Gorilla Tag", MB_OK);
            ExitProcess(0);
        }
        Sleep(3000);
    }
    return 0;
}
