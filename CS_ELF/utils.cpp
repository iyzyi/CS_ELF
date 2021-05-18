#include "stdafx.h"
#include "utils.h"

#include <windows.h>
#include <Tlhelp32.h>
#include <Shlwapi.h>  
#pragma comment(lib, "shlwapi.lib")



DWORD GetProcessIDByName(PCHAR pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe))
	{
		if (strcmp((PCHAR)pe.szExeFile, pName) == 0)
		{
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}



HMODULE hmCstrikeExe;
HMODULE hmMpDll;


BOOL GetModuleBaseAddress(DWORD dwPID) {
	HANDLE hSnapShot;
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	MODULEENTRY32 ModuleEntry32;
	ModuleEntry32.dwSize = sizeof(ModuleEntry32);
	if (Module32First(hSnapShot, &ModuleEntry32))
	{
		do
		{
			//printf("0x%x\t%s\n", ModuleEntry32.modBaseAddr, PathFindFileName(ModuleEntry32.szExePath));

			LPTSTR ModuleName = PathFindFileName(ModuleEntry32.szExePath);
			if (strcmp(ModuleName, "cstrike.exe") == 0) {
				hmCstrikeExe = (HMODULE)ModuleEntry32.modBaseAddr;
			}
			if (strcmp(ModuleName, "mp.dll") == 0) {
				hmMpDll = (HMODULE)ModuleEntry32.modBaseAddr;
			}
		} while (Module32Next(hSnapShot, &ModuleEntry32));
	}
	CloseHandle(hSnapShot);

	if (hmCstrikeExe != 0 && hmMpDll != 0) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}



int Run() {
	DWORD dwPID = GetProcessIDByName("cstrike.exe");
	if (dwPID == 0) {
		printf("请先运行游戏\n");
		return -1;
	}

	HANDLE hCS = OpenProcess(PROCESS_ALL_ACCESS, 1, dwPID);
	if (hCS == INVALID_HANDLE_VALUE) {
		printf("2222222\n");
		return -2;
	}

	if (!GetModuleBaseAddress(dwPID)) {
		return -3;
	}

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HealthPoint, hCS, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Bullet, hCS, 0, NULL);
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MoneyAndBuy, hCS, 0, NULL);
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NoRecoilGun, hCS, 0, NULL);

	return 0;
}


// 锁血
VOID WINAPI HealthPoint(HANDLE hCS) {
	DWORD dwPointer = 0;
	FLOAT fHealthPoint = 999.0f;
	DWORD dwIsNotMe = 1;

	while (1) {
		// 血量						[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0x160]
		// 判断是否是玩家而非BOT	[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0xa0]

		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x4), &dwPointer, sizeof(DWORD), NULL);

		ReadProcessMemory(hCS, LPVOID(dwPointer + 0xa0), &dwIsNotMe, sizeof(DWORD), NULL);
		if (dwIsNotMe == 0) {
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x160), &fHealthPoint, sizeof(FLOAT), NULL);
		}
	}
}


// 无限子弹
VOID WINAPI Bullet(HANDLE hCS) {
	DWORD dwPointer = 0;
	DWORD dwTmpPointer = 0;
	DWORD dwBulletNumber = 99;
	DWORD dwIsNotMe = 1;

	while (1) {
		// 当前枪的子弹数量			[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x5ec] + 0xcc]
		// 判断是否是玩家而非BOT	[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0xa0]

		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
		dwTmpPointer = dwPointer;

		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x4), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0xa0), &dwIsNotMe, sizeof(DWORD), NULL);
		if (dwIsNotMe == 0) {
			dwPointer = dwTmpPointer;
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x5ec), &dwPointer, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0xcc), &dwBulletNumber, sizeof(DWORD), NULL);
		}
	}
}


VOID WINAPI MoneyAndBuy(HANDLE hCS) {
	DWORD dwPointer = 0;
	DWORD dwTmpPointer = 0;
	DWORD dwMoney = 16000;
	DWORD dwCanBuy = 1;
	DWORD dwIsNotMe = 1;

	while (1) {
		// 金钱						[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x1cc]
		// 是否在商店范围			[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x3c0]
		// 判断是否是玩家而非BOT	[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0xa0]

		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
		dwTmpPointer = dwPointer;

		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x4), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0xa0), &dwIsNotMe, sizeof(DWORD), NULL);
		if (dwIsNotMe == 0) {
			dwPointer = dwTmpPointer;
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x1cc), &dwMoney, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x3c0), &dwCanBuy, sizeof(DWORD), NULL);
		}
	}
}


// 枪无后坐力
VOID WINAPI NoRecoilGun(HANDLE hCS) {
	DWORD dwPointer = 0;
	DWORD dwTmpPointer = 0;
	DWORD dwNum = 0;
	DWORD dwIsNotMe = 1;

	while (1) {
		// 枪在一定时间内发射了多少颗子弹（与后坐力有关）	[[[[Cstrike.exe + 0x11069bc] + 0x7c]  + 0x5ec] + 0x100]
		// 判断是否是玩家而非BOT							[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0xa0]

		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
		dwTmpPointer = dwPointer;

		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x4), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0xa0), &dwIsNotMe, sizeof(DWORD), NULL);
		if (dwIsNotMe == 0) {
			dwPointer = dwTmpPointer;
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x5ec), &dwPointer, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x100), &dwNum, sizeof(DWORD), NULL);
		}
	}
}