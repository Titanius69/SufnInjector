#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <cwchar>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <stdexcept>
#include <sddl.h>
#include <thread>
#include <chrono>
#include <vector>
#include <psapi.h>
#include <memoryapi.h>
#include <winternl.h> // NEW: NTSTATUS, OBJECT_ATTRIBUTES stb.

#pragma comment(lib, "ntdll.lib") // NEW: ntdll függvények linkeléséhez

#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

HANDLE hProcess = nullptr;
std::wstring targetProcessName;

const std::string INJECTOR_VERSION = "2.0"; // ManualMap + NT APIs + async restore
const std::vector<std::wstring> SUPPORTED_GAMES = { L"cs2.exe",
	L"csgo.exe",
	L"RustClient.exe",
	L"gmod.exe"
};

// NEW: globális változók az NtOpenFile hook visszaállításához
static BYTE g_OriginalNtOpenFileBytes[6] = { 0 };
static BOOL g_NtOpenFileBackedUp = FALSE;

// ========== NT API typedefs ==========
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE StartRoutine,
	LPVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID AttributeList
	);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
	);

typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType
	);

typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	int MemoryInformationClass, // 0 = MemoryBasicInformation
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
	);

// Shellcode param for ManualMap DllMain call
struct MANUAL_MAP_DATA {
	LPVOID pLoadLibraryA;
	LPVOID pGetProcAddress;
	LPVOID pbase;           // mapped image base in target
	HINSTANCE hMod;         // filled by shellcode = base on success
	DWORD fdwReason;
	LPVOID lpReserved;
};

namespace Helper {
	void SetConsoleColor(int color) {
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, color);
	}

	void PrintBanner() {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cout << "AnarchyInjector v" << INJECTOR_VERSION << std::endl << std::endl;
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "ManualMap + NT-API DLL injector for:" << std::endl;
		for (const std::wstring& game : SUPPORTED_GAMES) {
			std::wcout << L"- " << game << std::endl;
		}
		std::cout << "Features: ManualMap, NtCreateThreadEx, NtAllocate/Write, PE wipe, delayed hook restore" << std::endl;
		std::cout << "By: dest4590" << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
	}

	bool IsElevated() {
		BOOL fIsElevated = FALSE;
		HANDLE hToken = NULL;
		TOKEN_ELEVATION tokenElevation;
		DWORD dwSize;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}

		if (GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &dwSize)) {
			fIsElevated = tokenElevation.TokenIsElevated;
		}
		else {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "GetTokenInformation failed: " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
		}

		if (hToken) {
			CloseHandle(hToken);
		}
		return fIsElevated;
	}

	std::string GetFileNameFromPath(const std::string& path) {
		return std::filesystem::path(path).filename().string();
	}

	bool IsDigits(const std::string& str) {
		return std::all_of(str.begin(), str.end(), ::isdigit);
	}

	bool IsGameInSupportedList(const std::wstring& processName) {
		return std::any_of(SUPPORTED_GAMES.begin(), SUPPORTED_GAMES.end(),
			[&](const std::wstring& game) { return _wcsicmp(processName.c_str(), game.c_str()) == 0; });
	}

}

namespace ProcessUtils {
	HANDLE GetProcessByName(const std::wstring& processName) {
		DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
		if (Helper::IsElevated()) {
			desiredAccess = PROCESS_ALL_ACCESS;
		}

		PROCESSENTRY32W entry;
		entry.dwSize = sizeof(PROCESSENTRY32W);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot == INVALID_HANDLE_VALUE) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return NULL;
		}

		if (Process32FirstW(snapshot, &entry)) {
			do {
				if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
					DWORD processId = entry.th32ProcessID;
					HANDLE hProc = OpenProcess(desiredAccess, FALSE, processId);
					if (hProc != NULL) {
						CloseHandle(snapshot);
						targetProcessName = processName;
						return hProc;
					}
					else {
						Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
						std::wcerr << L"OpenProcess failed for process '" << processName << L"' (PID: " << processId << L"): " << GetLastError() << std::endl;
						Helper::SetConsoleColor(FOREGROUND_WHITE);
					}
				}
			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return NULL;
	}

	HANDLE GetProcessById(DWORD processId) {
		DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
		if (Helper::IsElevated()) {
			desiredAccess = PROCESS_ALL_ACCESS;
		}
		HANDLE hProc = OpenProcess(desiredAccess, FALSE, processId);
		if (hProc == NULL) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "OpenProcess failed for PID " << processId << ": " << GetLastError() << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
		}
		else {
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
			if (snapshot != INVALID_HANDLE_VALUE) {
				PROCESSENTRY32W entry;
				entry.dwSize = sizeof(PROCESSENTRY32W);
				if (Process32FirstW(snapshot, &entry)) {
					do {
						if (entry.th32ProcessID == processId) {
							targetProcessName = entry.szExeFile;
							break;
						}
					} while (Process32NextW(snapshot, &entry));
				}
				CloseHandle(snapshot);
			}
			else
			{
				Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
				std::cerr << "Warning: Could not retrieve process name for PID " << processId << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				targetProcessName = std::to_wstring(processId);
			}
		}
		return hProc;
	}
}

namespace ModuleUtils {
	// Finds the real base address of a loaded module by filename (works on x64).
	// GetExitCodeThread only returns the lower 32 bits of HMODULE – this is the correct way.
	LPVOID GetModuleBaseByName(HANDLE hProcess, const std::wstring& moduleFileName) {
		if (!hProcess || moduleFileName.empty()) return nullptr;

		std::vector<HMODULE> hModules(1024);
		DWORD cbNeeded = 0;

		if (!EnumProcessModules(hProcess, hModules.data(), static_cast<DWORD>(hModules.size() * sizeof(HMODULE)), &cbNeeded)) {
			if (cbNeeded > hModules.size() * sizeof(HMODULE)) {
				hModules.resize((cbNeeded / sizeof(HMODULE)) + 64);
				if (!EnumProcessModules(hProcess, hModules.data(), static_cast<DWORD>(hModules.size() * sizeof(HMODULE)), &cbNeeded)) {
					return nullptr;
				}
			}
			else {
				return nullptr;
			}
		}

		if (cbNeeded > hModules.size() * sizeof(HMODULE)) {
			hModules.resize(cbNeeded / sizeof(HMODULE) + 16);
			if (!EnumProcessModules(hProcess, hModules.data(), static_cast<DWORD>(hModules.size() * sizeof(HMODULE)), &cbNeeded)) {
				return nullptr;
			}
		}

		const DWORD moduleCount = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < moduleCount; ++i) {
			wchar_t szModuleName[MAX_PATH] = { 0 };
			if (GetModuleFileNameExW(hProcess, hModules[i], szModuleName, MAX_PATH)) {
				std::wstring fileName = std::filesystem::path(szModuleName).filename().wstring();
				if (_wcsicmp(fileName.c_str(), moduleFileName.c_str()) == 0) {
					return reinterpret_cast<LPVOID>(hModules[i]);
				}
			}
		}
		return nullptr;
	}

	bool WaitForModules(HANDLE hProcess, const std::vector<std::wstring>& moduleNames, DWORD timeoutMs) {
		auto startTime = std::chrono::steady_clock::now();
		std::vector<HMODULE> hModules(1024);
		DWORD cbNeeded;

		while (true) {
			if (!EnumProcessModules(hProcess, hModules.data(), static_cast<DWORD>(hModules.size() * sizeof(HMODULE)), &cbNeeded)) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "EnumProcessModules failed: " << GetLastError() << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return false;
			}

			if (cbNeeded > hModules.size() * sizeof(HMODULE)) {
				hModules.resize(cbNeeded / sizeof(HMODULE));
				continue;
			}

			int modulesFound = 0;
			for (const auto& moduleName : moduleNames) {
				for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
					wchar_t szModuleName[MAX_PATH];
					if (GetModuleFileNameExW(hProcess, hModules[i], szModuleName, MAX_PATH)) {
						std::wstring modulePath(szModuleName);
						std::wstring moduleFileName = std::filesystem::path(modulePath).filename().wstring();
						if (_wcsicmp(moduleFileName.c_str(), moduleName.c_str()) == 0) {
							modulesFound++;
							break;
						}
					}
				}
			}

			if (modulesFound == moduleNames.size()) {
				return true;
			}

			auto currentTime = std::chrono::steady_clock::now();
			auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
			if (elapsedTime > timeoutMs) {
				Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
				std::cerr << "Timeout waiting for modules." << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return false;
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}

namespace MemoryUtils {
	// Resolve NT APIs once
	static pNtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
	static pNtWriteVirtualMemory NtWriteVirtualMemory = nullptr;
	static pNtProtectVirtualMemory NtProtectVirtualMemory = nullptr;
	static pNtFreeVirtualMemory NtFreeVirtualMemory = nullptr;

	void InitNtApis() {
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		if (!ntdll) ntdll = LoadLibraryW(L"ntdll.dll");
		if (!ntdll) return;
		NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
		NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
		NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
		NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");
	}

	LPVOID NtAlloc(HANDLE hProcess, SIZE_T size, ULONG protect = PAGE_EXECUTE_READWRITE) {
		if (!NtAllocateVirtualMemory) InitNtApis();
		PVOID base = nullptr;
		SIZE_T regionSize = size;
		if (NtAllocateVirtualMemory) {
			NTSTATUS st = NtAllocateVirtualMemory(hProcess, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, protect);
			if (NT_SUCCESS(st)) return base;
		}
		// Fallback
		return VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
	}

	bool NtWrite(HANDLE hProcess, LPVOID address, LPCVOID buffer, SIZE_T size) {
		if (!NtWriteVirtualMemory) InitNtApis();
		SIZE_T written = 0;
		if (NtWriteVirtualMemory) {
			NTSTATUS st = NtWriteVirtualMemory(hProcess, address, (PVOID)buffer, size, &written);
			return NT_SUCCESS(st) && written == size;
		}
		return WriteProcessMemory(hProcess, address, buffer, size, &written) && written == size;
	}

	bool NtProtect(HANDLE hProcess, LPVOID address, SIZE_T size, ULONG newProtect, PULONG oldProtect) {
		if (!NtProtectVirtualMemory) InitNtApis();
		if (NtProtectVirtualMemory) {
			PVOID base = address;
			SIZE_T regionSize = size;
			NTSTATUS st = NtProtectVirtualMemory(hProcess, &base, &regionSize, newProtect, oldProtect);
			return NT_SUCCESS(st);
		}
		return VirtualProtectEx(hProcess, address, size, newProtect, oldProtect) != FALSE;
	}

	LPVOID FindFreeMemoryRegion(HANDLE hProcess, SIZE_T size) {
		MEMORY_BASIC_INFORMATION mbi;
		LPVOID address = NULL;

		while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
			if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
				return mbi.BaseAddress;
			}
			address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
		}

		return NULL;
	}

	bool WipePEHeaders(HANDLE hProcess, LPVOID baseAddress) {
		if (!hProcess || !baseAddress) {
			std::cerr << "[!] Invalid handle or address." << std::endl;
			return false;
		}

		// 5) Pre-check with VirtualQueryEx – skip if PAGE_NOACCESS / PAGE_GUARD
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (!VirtualQueryEx(hProcess, baseAddress, &mbi, sizeof(mbi))) {
			std::cerr << "[!] VirtualQueryEx failed, GLE=" << GetLastError() << std::endl;
			return false;
		}
		if (mbi.State != MEM_COMMIT) {
			std::cerr << "[!] Region is not committed (State=0x" << std::hex << mbi.State << std::dec << "). Skipping wipe." << std::endl;
			return false;
		}
		if (mbi.Protect == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) {
			std::cerr << "[!] Region is PAGE_NOACCESS or PAGE_GUARD (Protect=0x" << std::hex << mbi.Protect
				<< std::dec << "). Skipping wipe." << std::endl;
			return false;
		}

		IMAGE_DOS_HEADER dosHeader = { 0 };
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
			std::cerr << "[!] ReadProcessMemory (DOS header) failed, GLE=" << GetLastError() << std::endl;
			return false;
		}
		if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
			std::cerr << "[!] Invalid DOS signature (not MZ)." << std::endl;
			return false;
		}

		IMAGE_NT_HEADERS ntHeaders = { 0 };
		LPVOID ntHeadersAddr = (PBYTE)baseAddress + dosHeader.e_lfanew;
		if (!ReadProcessMemory(hProcess, ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead) || bytesRead != sizeof(IMAGE_NT_HEADERS)) {
			std::cerr << "[!] ReadProcessMemory (NT headers) failed, GLE=" << GetLastError() << std::endl;
			return false;
		}
		if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
			std::cerr << "[!] Invalid NT signature (not PE)." << std::endl;
			return false;
		}

		SIZE_T headersSize = ntHeaders.OptionalHeader.SizeOfHeaders;
		if (headersSize == 0) headersSize = 0x1000;
		if (headersSize > 0x10000) {
			std::cerr << "[!] Headers size too large: " << headersSize << std::endl;
			return false;
		}

		ULONG oldProtect = 0;
		if (!NtProtect(hProcess, baseAddress, headersSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			std::cerr << "[!] NtProtect / VirtualProtectEx failed, GLE=" << GetLastError() << std::endl;
			return false;
		}

		std::vector<BYTE> zeroBuffer(headersSize, 0);
		bool success = NtWrite(hProcess, baseAddress, zeroBuffer.data(), headersSize);

		ULONG tmp = 0;
		NtProtect(hProcess, baseAddress, headersSize, oldProtect, &tmp);

		if (!success) {
			std::cerr << "[!] Failed to zero PE headers." << std::endl;
			return false;
		}

		std::cout << "[+] PE headers wiped successfully (" << headersSize << " bytes)." << std::endl;
		return true;
	}
}

LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");

namespace Injection {
	// CHANGED: valódi bypass/backup implementáció
	void bypass(HANDLE hProcess) {
		if (!ntOpenFile) return;
		if (g_NtOpenFileBackedUp) return; // már mentve

		// 1. Mentsük el a jelenlegi (VAC által hookolt) bájtokat a cél folyamatból
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProcess, ntOpenFile, g_OriginalNtOpenFileBytes, sizeof(g_OriginalNtOpenFileBytes), &bytesRead) || bytesRead != sizeof(g_OriginalNtOpenFileBytes)) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Failed to backup NtOpenFile bytes from target!" << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return;
		}
		g_NtOpenFileBackedUp = TRUE;

		// 2. Írjuk vissza a tiszta bájtokat a mi ntdll-ünkből a célba
		BYTE cleanBytes[6] = { 0 };
		memcpy(cleanBytes, ntOpenFile, sizeof(cleanBytes)); // a mi saját processzünk NtOpenFile-ja tiszta

		DWORD oldProtect = 0;
		VirtualProtectEx(hProcess, ntOpenFile, sizeof(cleanBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
		SIZE_T bytesWritten = 0;
		WriteProcessMemory(hProcess, ntOpenFile, cleanBytes, sizeof(cleanBytes), &bytesWritten);
		VirtualProtectEx(hProcess, ntOpenFile, sizeof(cleanBytes), oldProtect, &oldProtect);

		if (bytesWritten == sizeof(cleanBytes)) {
			Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			std::cout << "[+] NtOpenFile bypassed (VAC hook overwritten with clean bytes)." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
		}
	}

	void backup(HANDLE hProcess) {
		if (!ntOpenFile || !g_NtOpenFileBackedUp) return;

		// Visszaállítjuk az eredeti (VAC által hookolt) bájtokat
		DWORD oldProtect = 0;
		VirtualProtectEx(hProcess, ntOpenFile, sizeof(g_OriginalNtOpenFileBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
		SIZE_T bytesWritten = 0;
		WriteProcessMemory(hProcess, ntOpenFile, g_OriginalNtOpenFileBytes, sizeof(g_OriginalNtOpenFileBytes), &bytesWritten);
		VirtualProtectEx(hProcess, ntOpenFile, sizeof(g_OriginalNtOpenFileBytes), oldProtect, &oldProtect);

		if (bytesWritten == sizeof(g_OriginalNtOpenFileBytes)) {
			Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			std::cout << "[+] NtOpenFile restored to original (VAC hook re-applied)." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
		}
		g_NtOpenFileBackedUp = FALSE;
	}

	// ========== Manual Map shellcode (x64) – resolves imports + calls DllMain ==========
	// This is position-independent code that runs inside the target process.
#pragma runtime_checks("", off)
#pragma optimize("", off)
	static void __stdcall ManualMapShellcode(MANUAL_MAP_DATA* pData) {
		if (!pData) return;

		BYTE* pBase = (BYTE*)pData->pbase;
		auto* pOpt = &((IMAGE_NT_HEADERS*)(pBase + ((IMAGE_DOS_HEADER*)pBase)->e_lfanew))->OptionalHeader;

		auto _LoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))pData->pLoadLibraryA;
		auto _GetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))pData->pGetProcAddress;
		auto _DllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))(pBase + pOpt->AddressOfEntryPoint);

		// Relocations
		BYTE* locationDelta = pBase - pOpt->ImageBase;
		if (locationDelta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress) {
				WORD* pRelativeInfo = (WORD*)(pRelocData + 1);
				UINT amount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				for (UINT i = 0; i < amount; ++i, ++pRelativeInfo) {
					if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_DIR64) {
						UINT_PTR* pPatch = (UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += (UINT_PTR)locationDelta;
					}
					else if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_HIGHLOW) {
						DWORD* pPatch = (DWORD*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += (DWORD)(UINT_PTR)locationDelta;
					}
				}
				pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
			}
		}

		// Imports
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
			auto* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDescr->Name) {
				char* szMod = (char*)(pBase + pImportDescr->Name);
				HMODULE hDll = _LoadLibraryA(szMod);

				ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
				ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);
				if (!pImportDescr->OriginalFirstThunk)
					pThunkRef = pFuncRef;

				for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
					if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
						*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (LPCSTR)(*pThunkRef & 0xFFFF));
					}
					else {
						auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
						*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
					}
				}
				++pImportDescr;
			}
		}

		// TLS callbacks
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
			auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
			if (pCallback) {
				while (*pCallback) {
					(*pCallback)((LPVOID)pBase, DLL_PROCESS_ATTACH, nullptr);
					++pCallback;
				}
			}
		}

		_DllMain((HINSTANCE)pBase, pData->fdwReason, pData->lpReserved);
		pData->hMod = (HINSTANCE)pBase;
	}
#pragma optimize("", on)
#pragma runtime_checks("", restore)

	// Marker for shellcode size (function after shellcode)
	static void ManualMapShellcodeEnd() {}

	bool ManualMapDll(const std::string& absoluteDllPath, HANDLE hProcess) {
		MemoryUtils::InitNtApis();

		// 1. Read file
		std::ifstream file(absoluteDllPath, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: Cannot open DLL: " << absoluteDllPath << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}
		std::streamsize fileSize = file.tellg();
		if (fileSize < 0x1000) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: DLL file too small." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}
		std::vector<BYTE> rawData((size_t)fileSize);
		file.seekg(0, std::ios::beg);
		file.read((char*)rawData.data(), fileSize);
		file.close();

		// 2. Validate PE
		auto* pDos = (IMAGE_DOS_HEADER*)rawData.data();
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
			std::cerr << "[!] Invalid DOS signature." << std::endl;
			return false;
		}
		auto* pNT = (IMAGE_NT_HEADERS*)(rawData.data() + pDos->e_lfanew);
		if (pNT->Signature != IMAGE_NT_SIGNATURE) {
			std::cerr << "[!] Invalid NT signature." << std::endl;
			return false;
		}
		if (pNT->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
			std::cerr << "[!] Only x64 DLLs are supported for ManualMap." << std::endl;
			return false;
		}

		SIZE_T imageSize = pNT->OptionalHeader.SizeOfImage;
		Helper::SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "[*] ManualMap: ImageSize = 0x" << std::hex << imageSize << std::dec << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);

		// 3. Allocate in target (NT API preferred)
		LPVOID pTargetBase = MemoryUtils::NtAlloc(hProcess, imageSize, PAGE_EXECUTE_READWRITE);
		if (!pTargetBase) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: NtAlloc / VirtualAllocEx failed for image." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}
		Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "[+] Target memory allocated at " << pTargetBase << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);

		// 4. Copy headers
		if (!MemoryUtils::NtWrite(hProcess, pTargetBase, rawData.data(), pNT->OptionalHeader.SizeOfHeaders)) {
			std::cerr << "[!] Failed to write PE headers." << std::endl;
			return false;
		}

		// 5. Copy sections
		auto* pSection = IMAGE_FIRST_SECTION(pNT);
		for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; ++i, ++pSection) {
			if (pSection->SizeOfRawData == 0) continue;
			LPVOID pDest = (BYTE*)pTargetBase + pSection->VirtualAddress;
			if (!MemoryUtils::NtWrite(hProcess, pDest, rawData.data() + pSection->PointerToRawData, pSection->SizeOfRawData)) {
				std::cerr << "[!] Failed to write section: " << (char*)pSection->Name << std::endl;
				return false;
			}
		}
		std::cout << "[+] Sections written." << std::endl;

		// 6. Prepare mapping data + shellcode
		MANUAL_MAP_DATA mapData = { 0 };
		mapData.pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		mapData.pGetProcAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
		mapData.pbase = pTargetBase;
		mapData.fdwReason = DLL_PROCESS_ATTACH;
		mapData.lpReserved = nullptr;
		mapData.hMod = nullptr;

		// Allocate + write mapData
		LPVOID pMapDataRemote = MemoryUtils::NtAlloc(hProcess, sizeof(MANUAL_MAP_DATA), PAGE_READWRITE);
		if (!pMapDataRemote || !MemoryUtils::NtWrite(hProcess, pMapDataRemote, &mapData, sizeof(mapData))) {
			std::cerr << "[!] Failed to write MANUAL_MAP_DATA." << std::endl;
			return false;
		}

		// Shellcode size
		SIZE_T shellcodeSize = (SIZE_T)((BYTE*)ManualMapShellcodeEnd - (BYTE*)ManualMapShellcode);
		if (shellcodeSize == 0 || shellcodeSize > 0x10000) {
			// Fallback size if compiler optimizes away the difference
			shellcodeSize = 0x1000;
		}

		LPVOID pShellcodeRemote = MemoryUtils::NtAlloc(hProcess, shellcodeSize, PAGE_EXECUTE_READWRITE);
		if (!pShellcodeRemote) {
			std::cerr << "[!] Failed to allocate shellcode memory." << std::endl;
			return false;
		}
		if (!MemoryUtils::NtWrite(hProcess, pShellcodeRemote, (LPCVOID)ManualMapShellcode, shellcodeSize)) {
			std::cerr << "[!] Failed to write shellcode." << std::endl;
			return false;
		}
		std::cout << "[+] Shellcode written (" << shellcodeSize << " bytes)." << std::endl;

		// 7. Execute via NtCreateThreadEx
		pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtCreateThreadEx");
		HANDLE hThread = NULL;
		BOOL threadCreated = FALSE;

		if (NtCreateThreadEx) {
			NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
				(LPTHREAD_START_ROUTINE)pShellcodeRemote, pMapDataRemote, 0, 0, 0, 0, NULL);
			if (NT_SUCCESS(status)) {
				threadCreated = TRUE;
				Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				std::cout << "[+] ManualMap thread created via NtCreateThreadEx." << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
			}
		}
		if (!threadCreated) {
			hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcodeRemote, pMapDataRemote, 0, nullptr);
			if (!hThread) {
				std::cerr << "[!] CreateRemoteThread failed for ManualMap: " << GetLastError() << std::endl;
				return false;
			}
			std::cout << "[+] ManualMap thread created via CreateRemoteThread (fallback)." << std::endl;
		}

		// Wait for mapping to finish
		WaitForSingleObject(hThread, 15000); // 15s timeout
		CloseHandle(hThread);

		// Read back hMod to confirm success
		MANUAL_MAP_DATA resultData = { 0 };
		SIZE_T bytesRead = 0;
		ReadProcessMemory(hProcess, pMapDataRemote, &resultData, sizeof(resultData), &bytesRead);

		if (resultData.hMod) {
			Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			std::cout << "[+] ManualMap succeeded. Module base: " << resultData.hMod << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);

			// Wipe headers (optional but recommended – leaves less PE signature)
			MemoryUtils::WipePEHeaders(hProcess, pTargetBase);
		}
		else {
			Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
			std::cerr << "Warning: ManualMap shellcode did not report success (hMod is null). DLL may still be mapped." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			// Still try to wipe
			MemoryUtils::WipePEHeaders(hProcess, pTargetBase);
		}

		std::cout << "[+] ManualMap injection completed." << std::endl;
		return true;
	}

	// CHANGED: NtCreateThreadEx + ManualMap path
	bool InjectDll(const std::string& path, HANDLE hProcess) {
		std::filesystem::path dllPath = std::filesystem::absolute(path);
		std::string absoluteDllPath = dllPath.string();
		std::string dllFileName = Helper::GetFileNameFromPath(absoluteDllPath);

		Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::wcout << L"Attempting to inject DLL: " << std::wstring(dllFileName.begin(), dllFileName.end()) << L" into process: " << targetProcessName << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);

		std::ifstream file(absoluteDllPath);
		if (!file.good()) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: DLL file not found: " << absoluteDllPath << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}
		file.close();
		std::cout << "[+] DLL file found." << std::endl;

		if (dllFileName == "skeet.dll") {
			Helper::SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
			std::cout << "Performing skeet-specific injection..." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);

			bypass(hProcess);

			VirtualAllocEx(hProcess, (LPVOID)0x43310000, 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			VirtualAllocEx(hProcess, 0, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			LPVOID lpPathAddress = VirtualAllocEx(hProcess, nullptr, absoluteDllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (lpPathAddress == nullptr) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Error: VirtualAllocEx failed (skeet path alloc): " << GetLastError() << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return false;
			}
			Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			std::cout << "Memory allocated for path at address: " << lpPathAddress << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);

			if (!WriteProcessMemory(hProcess, lpPathAddress, absoluteDllPath.c_str(), absoluteDllPath.size() + 1, nullptr)) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Error: WriteProcessMemory failed (skeet path write): " << GetLastError() << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
				return false;
			}

			std::cout << "[+] DLL path written successfully." << std::endl;

			HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
			if (!hKernel32) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Error: GetModuleHandleA failed for kernel32.dll" << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
				return false;
			}

			FARPROC lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
			if (!lpLoadLibraryA) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Error: GetProcAddress failed for LoadLibraryA" << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
				return false;
			}
			std::cout << "[+] LoadLibraryA address found." << std::endl;

			// CHANGED: NtCreateThreadEx használata
			pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtCreateThreadEx");
			HANDLE hThread = NULL;
			BOOL threadCreated = FALSE;

			if (NtCreateThreadEx) {
				NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
					(LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpPathAddress, 0, 0, 0, 0, NULL);
				if (NT_SUCCESS(status)) {
					threadCreated = TRUE;
					Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
					std::cout << "[+] Remote thread created via NtCreateThreadEx." << std::endl;
					Helper::SetConsoleColor(FOREGROUND_WHITE);
				}
				else {
					Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
					std::cerr << "NtCreateThreadEx failed (status: 0x" << std::hex << status << "), falling back to CreateRemoteThread." << std::endl;
					Helper::SetConsoleColor(FOREGROUND_WHITE);
				}
			}

			if (!threadCreated) {
				hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpPathAddress, 0, nullptr);
				if (!hThread) {
					Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
					std::cerr << "Error: CreateRemoteThread failed (skeet injection): " << GetLastError() << std::endl;
					Helper::SetConsoleColor(FOREGROUND_WHITE);
					VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
					return false;
				}
				Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				std::cout << "Remote thread created via CreateRemoteThread (fallback)." << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
			}

			WaitForSingleObject(hThread, INFINITE);
			DWORD exitCode;
			GetExitCodeThread(hThread, &exitCode);

			// NEW: PE-fejlec törlése (skeet esetén, de csak a betöltött DLL-re, aminek a címét nem ismerjük itt – ezt az általános ágban csináljuk)
			// Itt a skeet saját memóriakezelése miatt nem töröljük a fejléceket.

			std::cout << "DLL ";
			Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			std::wcout << std::wstring(dllFileName.begin(), dllFileName.end());
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			std::cout << " injected successfully into ";
			Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
			std::wcout << targetProcessName;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			std::cout << ", Return code: ";
			Helper::SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
			std::cout << exitCode << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);

			CloseHandle(hThread);
			backup(hProcess);
			std::cout << "[+] Injection completed (skeet)." << std::endl;
			return true;
		}
		else {
			// Default path: ManualMap (no LoadLibrary traces, headers wiped)
			Helper::SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
			std::cout << "[*] Using ManualMap injection (x64)..." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);

			if (!ManualMapDll(absoluteDllPath, hProcess)) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "ManualMap failed." << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return false;
			}

			std::cout << "DLL ";
			Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
			std::wcout << std::wstring(dllFileName.begin(), dllFileName.end());
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			std::cout << " injected successfully into ";
			Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
			std::wcout << targetProcessName;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			std::cout << " via ManualMap." << std::endl;
			return true;
		}
	}

	bool InjectAfterModulesLoaded(HANDLE hProcess, const std::string& dllPath, const std::vector<std::wstring>& moduleNames, DWORD timeoutMs) {
		if (!ModuleUtils::WaitForModules(hProcess, moduleNames, timeoutMs)) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Failed to wait for necessary modules." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}

		Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "All required modules found. Waiting 20 seconds..." << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);
		std::this_thread::sleep_for(std::chrono::seconds(20));

		return InjectDll(dllPath, hProcess);
	}
}

namespace HookBypass {
	void LoadLib() {
		if (!GetModuleHandleW(L"kernel32")) LoadLibraryW(L"kernel32");
		if (!GetModuleHandleW(L"ntdll")) LoadLibraryW(L"ntdll");
		if (!GetModuleHandleW(L"KernelBase")) LoadLibraryW(L"KernelBase");
	}

	BOOL UnhookMethod(const char* methodName, const wchar_t* dllName, PBYTE save_origin_bytes) {
		HMODULE hModule = GetModuleHandleW(dllName);
		if (!hModule) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::wcerr << L"Error: GetModuleHandleW failed for " << dllName << L" (" << GetLastError() << L")" << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		LPVOID oriMethodAddr = GetProcAddress(hModule, methodName);
		if (!oriMethodAddr) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetProcAddress failed for " << methodName << " in " << dllName << " (" << GetLastError() << ")" << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		PBYTE originalGameBytes[6];
		if (!ReadProcessMemory(hProcess, oriMethodAddr, originalGameBytes, sizeof(char) * 6, NULL)) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: ReadProcessMemory failed for " << methodName << " in " << dllName << ": " << GetLastError() << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}

		if (save_origin_bytes != nullptr) {
			memcpy(save_origin_bytes, originalGameBytes, sizeof(char) * 6);
		}


		PBYTE originalDllBytes[6];
		memcpy(originalDllBytes, oriMethodAddr, sizeof(char) * 6);
		if (!WriteProcessMemory(hProcess, oriMethodAddr, originalDllBytes, sizeof(char) * 6, NULL)) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: WriteProcessMemory failed for " << methodName << " in " << dllName << ": " << GetLastError() << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		return TRUE;
	}

	BOOL RestoreOriginalHook(const char* methodName, const wchar_t* dllName, PBYTE save_origin_bytes) {
		HMODULE hModule = GetModuleHandleW(dllName);
		if (!hModule) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::wcerr << L"Error: GetModuleHandleW failed for " << dllName << L" (" << GetLastError() << L")" << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		LPVOID oriMethodAddr = GetProcAddress(hModule, methodName);
		if (!oriMethodAddr) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetProcAddress failed for " << methodName << " in " << dllName << " (" << GetLastError() << ")" << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		if (!WriteProcessMemory(hProcess, oriMethodAddr, save_origin_bytes, sizeof(char) * 6, NULL)) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: WriteProcessMemory failed for " << methodName << " in " << dllName << ": " << GetLastError() << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		return TRUE;
	}

	enum MethodNum {
		LOADLIBEXW = 1,
		VIRALLOC = 2,
		FREELIB = 3,
		LOADLIBEXA = 4,
		LOADLIBW = 5,
		LOADLIBA = 6,
		VIRALLOCEX = 7,
		LDRLOADDLL = 10,
		NTOPENFILE = 11,
		VIRPROT = 12,
		CREATPROW = 13,
		CREATPROA = 14,
		VIRPROTEX = 15,
		FREELIB_ = 16,
		LOADLIBEXA_ = 17,
		LOADLIBEXW_ = 18,
		RESUMETHREAD = 19,
	};
	BYTE originalGameBytess[30][6];
	BOOL BypassCSGO_hook(bool disableAll = false) {
		BOOL res = TRUE;
		if (!disableAll)
		{
			res &= UnhookMethod("LoadLibraryExW", L"kernel32", originalGameBytess[LOADLIBEXW]);
			res &= UnhookMethod("VirtualAlloc", L"kernel32", originalGameBytess[VIRALLOC]);
			res &= UnhookMethod("FreeLibrary", L"kernel32", originalGameBytess[FREELIB]);
			res &= UnhookMethod("LoadLibraryExA", L"kernel32", originalGameBytess[LOADLIBEXA]);
			res &= UnhookMethod("LoadLibraryW", L"kernel32", originalGameBytess[LOADLIBW]);
			res &= UnhookMethod("LoadLibraryA", L"kernel32", originalGameBytess[LOADLIBA]);
			res &= UnhookMethod("VirtualAllocEx", L"kernel32", originalGameBytess[VIRALLOCEX]);
			res &= UnhookMethod("LdrLoadDll", L"ntdll", originalGameBytess[LDRLOADDLL]);
			res &= UnhookMethod("NtOpenFile", L"ntdll", originalGameBytess[NTOPENFILE]);
			res &= UnhookMethod("VirtualProtect", L"kernel32", originalGameBytess[VIRPROT]);
			res &= UnhookMethod("CreateProcessW", L"kernel32", originalGameBytess[CREATPROW]);
			res &= UnhookMethod("CreateProcessA", L"kernel32", originalGameBytess[CREATPROA]);
			res &= UnhookMethod("VirtualProtectEx", L"kernel32", originalGameBytess[VIRPROTEX]);
			res &= UnhookMethod("FreeLibrary", L"KernelBase", originalGameBytess[FREELIB_]);
			res &= UnhookMethod("LoadLibraryExA", L"KernelBase", originalGameBytess[LOADLIBEXA_]);
			res &= UnhookMethod("LoadLibraryExW", L"KernelBase", originalGameBytess[LOADLIBEXW_]);
			res &= UnhookMethod("ResumeThread", L"KernelBase", originalGameBytess[RESUMETHREAD]);
		}
		else {
			res &= UnhookMethod("LoadLibraryExW", L"kernel32", nullptr);
			res &= UnhookMethod("VirtualAlloc", L"kernel32", nullptr);
			res &= UnhookMethod("FreeLibrary", L"kernel32", nullptr);
			res &= UnhookMethod("LoadLibraryExA", L"kernel32", nullptr);
			res &= UnhookMethod("LoadLibraryW", L"kernel32", nullptr);
			res &= UnhookMethod("LoadLibraryA", L"kernel32", nullptr);
			res &= UnhookMethod("VirtualAllocEx", L"kernel32", nullptr);
			res &= UnhookMethod("LdrLoadDll", L"ntdll", nullptr);
			res &= UnhookMethod("NtOpenFile", L"ntdll", nullptr);
			res &= UnhookMethod("VirtualProtect", L"kernel32", nullptr);
			res &= UnhookMethod("CreateProcessW", L"kernel32", nullptr);
			res &= UnhookMethod("CreateProcessA", L"kernel32", nullptr);
			res &= UnhookMethod("VirtualProtectEx", L"kernel32", nullptr);
			res &= UnhookMethod("FreeLibrary", L"KernelBase", nullptr);
			res &= UnhookMethod("LoadLibraryExA", L"KernelBase", nullptr);
			res &= UnhookMethod("LoadLibraryExW", L"KernelBase", nullptr);
			res &= UnhookMethod("ResumeThread", L"KernelBase", nullptr);

		}

		return res;
	}

	BOOL RestoreCSGO_hook() {
		BOOL res = TRUE;
		res &= RestoreOriginalHook("LoadLibraryExW", L"kernel32", originalGameBytess[LOADLIBEXW]);
		res &= RestoreOriginalHook("VirtualAlloc", L"kernel32", originalGameBytess[VIRALLOC]);
		res &= RestoreOriginalHook("FreeLibrary", L"kernel32", originalGameBytess[FREELIB]);
		res &= RestoreOriginalHook("LoadLibraryExA", L"kernel32", originalGameBytess[LOADLIBEXA]);
		res &= RestoreOriginalHook("LoadLibraryW", L"kernel32", originalGameBytess[LOADLIBW]);
		res &= RestoreOriginalHook("LoadLibraryA", L"kernel32", originalGameBytess[LOADLIBA]);
		res &= RestoreOriginalHook("VirtualAllocEx", L"kernel32", originalGameBytess[VIRALLOCEX]);
		res &= RestoreOriginalHook("LdrLoadDll", L"ntdll", originalGameBytess[LDRLOADDLL]);
		res &= RestoreOriginalHook("NtOpenFile", L"ntdll", originalGameBytess[NTOPENFILE]);
		res &= RestoreOriginalHook("VirtualProtect", L"kernel32", originalGameBytess[VIRPROT]);
		res &= RestoreOriginalHook("CreateProcessW", L"kernel32", originalGameBytess[CREATPROW]);
		res &= RestoreOriginalHook("CreateProcessA", L"kernel32", originalGameBytess[CREATPROA]);
		res &= RestoreOriginalHook("VirtualProtectEx", L"kernel32", originalGameBytess[VIRPROTEX]);
		res &= RestoreOriginalHook("FreeLibrary", L"KernelBase", originalGameBytess[FREELIB_]);
		res &= RestoreOriginalHook("LoadLibraryExA", L"KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= RestoreOriginalHook("LoadLibraryExW", L"KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= RestoreOriginalHook("ResumeThread", L"KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
}

namespace SteamInjection {
	bool InjectSteamDll(const std::string& dllPath) {
		std::string cheatName = Helper::GetFileNameFromPath(dllPath);
		cheatName = cheatName.substr(0, cheatName.find_last_of("."));
		std::string steamDllName = "steam_" + cheatName + ".dll";
		std::filesystem::path injectorPath = std::filesystem::absolute(dllPath).parent_path();
		std::filesystem::path steamDllPath = injectorPath / steamDllName;
		std::string steamDllPathStr = steamDllPath.string();

		if (std::filesystem::exists(steamDllPath)) {
			Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
			std::cout << "Found Steam DLL: " << steamDllName << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);

			HANDLE hSteamProcess = ProcessUtils::GetProcessByName(L"steam.exe");
			if (hSteamProcess) {
				targetProcessName = L"steam.exe";
				if (!Injection::InjectDll(steamDllPathStr, hSteamProcess)) {
					Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
					std::cerr << "Failed to inject into steam.exe" << std::endl;
					Helper::SetConsoleColor(FOREGROUND_WHITE);
					CloseHandle(hSteamProcess);
					return false;
				}
				else {
					Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
					std::cout << "Successfully injected " << steamDllName << " into steam.exe" << std::endl;
					Helper::SetConsoleColor(FOREGROUND_WHITE);
					CloseHandle(hSteamProcess);
					return true;
				}
			}
			else {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Could not find steam.exe. Skipping Steam DLL injection." << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return false;
			}
		}
		else {
			return false;
		}
	}
}

namespace GameSpecific {
	std::vector<std::wstring> GetModulesToWaitFor(const std::wstring& processName) {
		if (processName == L"cs2.exe") {
			return {
				L"client.dll",
					L"engine2.dll",
					L"server.dll"
			};
		}
		else if (processName == L"csgo.exe") {
			return {
			  L"client.dll",
			  L"engine.dll",
			  L"server.dll"
			};
		}
		else if (processName == L"RustClient.exe")
		{
			return {
			   L"GameAssembly.dll",
			   L"UnityPlayer.dll"
			};
		}
		else if (processName == L"gmod.exe")
		{
			return {
			   L"client.dll",
			   L"engine.dll"
			};
		}
		return {};
	}

	bool ApplyHookBypass(const std::wstring& processName, bool disableHooks) {
		if (processName == L"cs2.exe" || processName == L"csgo.exe") {
			if (!HookBypass::BypassCSGO_hook(disableHooks)) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Failed to bypass VAC hooks!" << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				if (!disableHooks) {
					if (!HookBypass::RestoreCSGO_hook()) {
						Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
						std::cerr << "Failed to restore VAC hooks.  This is VERY dangerous." << std::endl;
						Helper::SetConsoleColor(FOREGROUND_WHITE);
					}
				}
				return false;
			}
			if (!disableHooks)
			{
				std::cout << "[+] VAC hooks bypassed." << std::endl;
			}
			else
			{
				std::cout << "[+] VAC bypass not applied as the target process is steam." << std::endl;
			}

		}
		else
		{
			return true;
		}
		return true;
	}

	bool RestoreHookBypass(const std::wstring& processName) {
		if (processName == L"cs2.exe" || processName == L"csgo.exe") {
			if (!HookBypass::RestoreCSGO_hook()) {
				Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
				std::cerr << "Warning: Failed to restore VAC hooks! This may result in a VAC ban." << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return false;
			}
			else {
				std::cout << "[+] VAC hooks restored." << std::endl;
				return true;
			}
		}
		return true;
	}
}

int main(int argc, char* argv[]) {
	SetConsoleTitleA("AnarchyInjector");

	if (argc == 1) {
		Helper::PrintBanner();
	}

	if (Helper::IsElevated()) {
		Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "[+] Injector is running with administrator privileges." << std::endl;
	}

	Helper::SetConsoleColor(FOREGROUND_WHITE);
	std::cout << std::endl;

	std::string dllPath;
	std::string processNameOrId;
	std::string exeName = std::filesystem::path(argv[0]).filename().string();

	if (argc == 2) {
		dllPath = argv[1];
	}
	else if (argc == 3) {
		processNameOrId = argv[1];
		dllPath = argv[2];
	}
	else {
		Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cerr << "Usage: " << exeName << " <dll_path>\nOR: " << exeName << " <process_name_or_PID> <dll_path>" << std::endl << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);

		system("pause");
		return 1;
	}

	bool injectedIntoSteam = false;

	bool isSupportedGame = false;
	if (!processNameOrId.empty()) {
		std::wstring wProcessName(processNameOrId.begin(), processNameOrId.end());
		isSupportedGame = Helper::IsGameInSupportedList(wProcessName);
	}
	else {
		isSupportedGame = true;
	}

	if (isSupportedGame) {
		injectedIntoSteam = SteamInjection::InjectSteamDll(dllPath);
	}

	if (processNameOrId.empty()) {
		Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cout << "Please launch the target process..." << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);

		bool gameFound = false;
		for (int i = 0; i < 60; ++i) {
			for (const auto& game : SUPPORTED_GAMES) {
				hProcess = ProcessUtils::GetProcessByName(game);
				if (hProcess) {
					targetProcessName = game;
					gameFound = true;
					break;
				}
			}
			if (gameFound)
				break;
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		if (!gameFound) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Timeout: Target process not launched within the waiting period." << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return 1;
		}
	}
	else {
		if (Helper::IsDigits(processNameOrId)) {
			try {
				DWORD processId = std::stoi(processNameOrId);
				hProcess = ProcessUtils::GetProcessById(processId);
			}
			catch (const std::invalid_argument&) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Invalid process ID: " << processNameOrId << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return 1;
			}
			catch (const std::out_of_range&) {
				Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Process ID out of range: " << processNameOrId << std::endl;
				Helper::SetConsoleColor(FOREGROUND_WHITE);
				return 1;
			}
		}
		else {
			std::wstring wProcessName(processNameOrId.begin(), processNameOrId.end());
			hProcess = ProcessUtils::GetProcessByName(wProcessName);
		}

		if (!hProcess) {
			Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Can not find process: " << processNameOrId << std::endl;
			Helper::SetConsoleColor(FOREGROUND_WHITE);
			return 1;
		}
	}

	Helper::SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	std::wcout << L"Process found: " << targetProcessName << std::endl;
	Helper::SetConsoleColor(FOREGROUND_WHITE);

	std::string dllFileName = Helper::GetFileNameFromPath(dllPath);

	bool disableBypass = injectedIntoSteam;
	if (isSupportedGame && dllFileName != "skeet.dll")
	{
		if (!GameSpecific::ApplyHookBypass(targetProcessName, disableBypass))
		{
			CloseHandle(hProcess);
			return 1;
		}

	}

	// Run injection (ManualMap / skeet path). Hooks stay bypassed during this.
	bool injectOk = Injection::InjectDll(dllPath, hProcess);

	if (!injectOk) {
		Helper::SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "Failed to inject DLL." << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);
		GameSpecific::RestoreHookBypass(targetProcessName);
		CloseHandle(hProcess);
		return 1;
	}

	// 4) Delayed hook restore – give DllMain / init code a short window before VAC hooks return
	if ((isSupportedGame && !disableBypass) && dllFileName != "skeet.dll")
	{
		Helper::SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cout << "[*] Waiting 2 seconds before restoring VAC hooks..." << std::endl;
		Helper::SetConsoleColor(FOREGROUND_WHITE);
		std::this_thread::sleep_for(std::chrono::seconds(2));

		// Async-style: restore on a detached thread so main can exit cleanly
		std::wstring procNameCopy = targetProcessName;
		std::thread restoreThread([procNameCopy]() {
			GameSpecific::RestoreHookBypass(procNameCopy);
			});
		restoreThread.detach();
		// Give the restore thread a moment to finish before we close the process handle
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	CloseHandle(hProcess);
	return 0;
}