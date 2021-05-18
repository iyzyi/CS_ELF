#include "stdafx.h"
//#include "stdio.h"
#include "utils.h"
//#include "stdlib.hs"

#ifndef _DEBUG
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

#endif


#ifdef _DEBUG
int main() {
	Run();
	system("pause");
	return 0;
}

#endif