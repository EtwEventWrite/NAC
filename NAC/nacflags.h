#pragma once
#include <Windows.h>
#include <stdio.h>

typedef enum NAC_FLAG_ID {
	FLAG_SECUREBOOT_OFF = 1,
	FLAG_PRIVATE_EXEC_REGION = 2,
	FLAG_RWX_REGION = 3,
	FLAG_SUSP_THREAD_START = 4,
	FLAG_UNKNOWN_MODULE = 5
} NAC_FLAG_ID;

typedef struct NAC_FLAG_EVENT {
	NAC_FLAG_ID id;
	int points;
	DWORD tick;
	char detail[256];
} NAC_FLAG_EVENT;

typedef struct NAC_STATE {
	volatile LONG score;
	DWORD last_decay_tick;
	NAC_FLAG_EVENT last_events[16];
	int last_event_idx;
} NAC_STATE;

static NAC_STATE g_nac = { 0 };

static void NAC_AddFlag(NAC_FLAG_ID id, int points, const char* detail) {
	LONG newscore = InterlockedAdd(&g_nac.score, points);
	DWORD now = GetTickCount();
	int idx = g_nac.last_event_idx++ & 15;
	g_nac.last_events[idx].id = id;
	g_nac.last_events[idx].points = points;
	g_nac.last_events[idx].tick = now;
	strncpy_s(g_nac.last_events[idx].detail, sizeof(g_nac.last_events[idx].detail), detail ? detail : "", _TRUNCATE);
	printf("[flagged] +%d (id=%d) score=%ld detail=%s\n", points, (int)id, newscore, detail ? detail : "");
}

static void NAC_DecayScore(void) {
	DWORD now = GetTickCount();
	if (g_nac.last_decay_tick == 0) g_nac.last_decay_tick = now;
	while (now - g_nac.last_decay_tick >= 60000) {
		LONG cur = g_nac.score;
		if (cur > 0) InterlockedDecrement(&g_nac.score);
		g_nac.last_decay_tick += 60000;
	}
}

static LONG NAC_GetScore(void) {
	return g_nac.score;
}