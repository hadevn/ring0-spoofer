#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <accctrl.h>
#include <aclapi.h>
#include <shlobj_core.h>
#include <tlhelp32.h>

typedef NTSTATUS(WINAPI* NTQK)(HANDLE KeyHandle, DWORD KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTQK NtQueryKey;

BOOL AdjustCurrentPrivilege(LPCWSTR privilege)
{
	LUID luid = { 0 };
	if (!LookupPrivilegeValue(0, privilege, &luid))
	{
		printf("Failed to lookup privilege %ws: %d\n", privilege, GetLastError());
		return FALSE;
	}

	TOKEN_PRIVILEGES tp = { 0 };
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	HANDLE token = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		return FALSE;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), 0, 0))
	{
		CloseHandle(token);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		CloseHandle(token);
		return FALSE;
	}

	CloseHandle(token);
	return TRUE;
}

VOID ForceDeleteFile(LPWSTR path)
{
	if (!PathFileExists(path))
	{
		return;
	}

	PSID all = 0, admin = 0;
	SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
	if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &all))
	{
		return;
	}

	SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin))
	{
		FreeSid(all);
		return;
	}

	EXPLICIT_ACCESS access[2] = { 0 };
	access[0].grfAccessPermissions = GENERIC_ALL;
	access[0].grfAccessMode = SET_ACCESS;
	access[0].grfInheritance = NO_INHERITANCE;
	access[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	access[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	access[0].Trustee.ptstrName = all;
	access[1].grfAccessPermissions = GENERIC_ALL;
	access[1].grfAccessMode = SET_ACCESS;
	access[1].grfInheritance = NO_INHERITANCE;
	access[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	access[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	access[1].Trustee.ptstrName = admin;

	PACL acl = { 0 };
	DWORD error = SetEntriesInAcl(2, access, 0, &acl);
	if (ERROR_SUCCESS != error)
	{
		FreeSid(all);
		FreeSid(admin);
		return;
	}

	if (ERROR_SUCCESS != (error = SetNamedSecurityInfo((LPWSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, admin, 0, 0, 0)))
	{
		FreeSid(all);
		FreeSid(admin);
		LocalFree(acl);
		return;
	}

	if (ERROR_SUCCESS != (error = SetNamedSecurityInfo((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, acl, 0)))
	{
		FreeSid(all);
		FreeSid(admin);
		LocalFree(acl);
		return;
	}

	SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);

	SHFILEOPSTRUCT op = { 0 };
	op.wFunc = FO_DELETE;
	path[wcslen(path) + 1] = 0;
	op.pFrom = path;
	op.pTo = L"\0";
	op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
	op.lpszProgressTitle = L"";
	if (DeleteFile(path) || !SHFileOperation(&op))
	{
		printf("Deleted: %ws\n", path);
	}
	else
	{
	}

	FreeSid(all);
	FreeSid(admin);
	LocalFree(acl);
}

void ChangePermission()
{
	srand(GetTickCount());
	LoadLibrary(L"ntdll.dll");
	NtQueryKey = (NTQK)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryKey");
	if (!AdjustCurrentPrivilege(SE_TAKE_OWNERSHIP_NAME))
	{
		printf("failed to adjust privilege\n");
		return 1;
	}
}