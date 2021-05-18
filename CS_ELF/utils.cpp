#include "stdafx.h"
#include "utils.h"

#include <windows.h>
#include <Tlhelp32.h>
#include <Shlwapi.h>  
#pragma comment(lib, "shlwapi.lib")


DWORD			dwPID;
HANDLE			hCS;
HMODULE			hmCstrikeExe;
HMODULE			hmMpDll;

DWORD			dwPlayerAddress = 0;


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

	if (hmCstrikeExe != 0){
	//if (hmCstrikeExe != 0 && hmMpDll != 0) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}


int Run() {

	dwPID = GetProcessIDByName("cstrike.exe");
	if (dwPID == 0) {
		printf("����������Ϸ\n");
		return -1;
	}

	hCS = OpenProcess(PROCESS_ALL_ACCESS, 1, dwPID);
	if (hCS == INVALID_HANDLE_VALUE) {
		printf("GetProcessIDByNameʧ��\n");
		return -2;
	}

	if (!GetModuleBaseAddress(dwPID)) {
		printf("��ȡģ��ʧ��\n");
		return -3;
	}

	GetPlayerAddress();

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HealthPoint, NULL, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Bullet, NULL, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MoneyAndBuy, NULL, 0, NULL);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NoRecoilGun, NULL, 0, NULL);

	while (1) {}

	return 0;
}


// ��ȡ��ǰ��ҵĻ�ַ		[[Cstrike.exe + 0x1117c64] + 0x4b9c]
// Ӧע���[Cstrike.exe + 0x11069bc]��ȡ������ʱ�ǵ�ǰ��ҵĻ�ַ����ʱ������������ҵĻ�ַ���޷����֡�
VOID GetPlayerAddress() {
	printf("���ڻ�ȡ��ǰ��һ�ַ......\n");
	while (dwPlayerAddress == 0) {
		DWORD dwPointer = 0;
		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x1117c64), &dwPointer, sizeof(DWORD), NULL);
		ReadProcessMemory(hCS, LPVOID(dwPointer + 0x4b9c), &dwPlayerAddress, sizeof(DWORD), NULL);
	}
	printf("��ǰ��ҵĻ�ַΪ0x%x\n", dwPlayerAddress);
}


BOOL IsPlayer(DWORD dwTmpAddress) {
	return (dwPlayerAddress != 0 && dwPlayerAddress == dwTmpAddress);
}


// ��Ѫ + �˺�����
VOID WINAPI HealthPoint(LPVOID) {
	DWORD dwPointer = 0;
	FLOAT fHealthPoint = 999.0f;
	DWORD dwHarm = 0;

	while (1) {
		// Ѫ��				[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0x160] = 999.0f
		// �˺����� 		[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x4] + 0x16c] = 0
		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		if (IsPlayer(dwPointer)) {
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x4), &dwPointer, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x160), &fHealthPoint, sizeof(FLOAT), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x16c), &dwHarm, sizeof(FLOAT), NULL);
		}
	}
}


// �����ӵ�			[[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x5ec] + 0xcc] = 99
VOID WINAPI Bullet(LPVOID) {
	DWORD dwPointer = 0;
	DWORD dwBulletNumber = 99;

	while (1) {
		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		if (IsPlayer(dwPointer)) {
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x5ec), &dwPointer, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0xcc), &dwBulletNumber, sizeof(DWORD), NULL);
		}
	}
}


// ���޽�Ǯ ��ع���
VOID WINAPI MoneyAndBuy(LPVOID) {
	DWORD dwPointer = 0;
	DWORD dwMoney = 99999;
	DWORD dwCanBuy = 1;

	while (1) {
		// ��Ǯ						[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x1cc] = 16000
		// �Ƿ����̵귶Χ			[[[Cstrike.exe + 0x11069bc] + 0x7c] + 0x3c0] = 1
		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		if (IsPlayer(dwPointer)) {
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x1cc), &dwMoney, sizeof(DWORD), NULL);
			//WriteProcessMemory(hCS, LPVOID(dwPointer + 0x3c0), &dwCanBuy, sizeof(DWORD), NULL);
		}
	}
}


// ǹ�޺�����
// ǹ��һ��ʱ���ڷ����˶��ٿ��ӵ�����������йأ�	[[[[Cstrike.exe + 0x11069bc] + 0x7c]  + 0x5ec] + 0x100] = 0
VOID WINAPI NoRecoilGun(LPVOID) {
	DWORD dwPointer = 0;
	DWORD dwNum = 0;

	while (1) {
		ReadProcessMemory(hCS, LPVOID((DWORD)hmCstrikeExe + 0x11069bc), &dwPointer, sizeof(DWORD), NULL);
		if (IsPlayer(dwPointer)) {
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x7c), &dwPointer, sizeof(DWORD), NULL);
			ReadProcessMemory(hCS, LPVOID(dwPointer + 0x5ec), &dwPointer, sizeof(DWORD), NULL);
			WriteProcessMemory(hCS, LPVOID(dwPointer + 0x100), &dwNum, sizeof(DWORD), NULL);
		}
	}
}