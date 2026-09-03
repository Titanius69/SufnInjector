<div align="center">
   <img src="https://imgur.com/5CwCMlU.png" width="150"></img>
   <h1>SufnInjector</h1>
   SufnInjector is a ManualMap DLL injector for CS2, CS:GO and other games (originally based on AnarchyInjector / AnarchyLoader).
</div>

> [!CAUTION]
> Using this injector in online games is not recommended as it can result in a ban.
> Play at your own risk. This warning is given to avoid any negative consequences. Be responsible.

## Old → New (v1.x → v2.0)

| Area | Old (AnarchyInjector ~1.5) | New (SufnInjector 2.0) |
|------|----------------------------|-------------------------|
| **Name** | AnarchyInjector | **SufnInjector** |
| **Injection method** | LoadLibraryA + remote thread | **ManualMap** (default) – own PE loader, sections, relocs, imports, TLS, DllMain |
| **Thread creation** | CreateRemoteThread (fallback NtCreateThreadEx) | **NtCreateThreadEx** first, CreateRemoteThread fallback |
| **Memory APIs** | VirtualAllocEx / WriteProcessMemory / VirtualProtectEx | **NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory** (with WinAPI fallback) |
| **PE headers** | Optional wipe via truncated GetExitCodeThread (broken on x64) | Real base via **EnumProcessModules**; wipe after ManualMap; **VirtualQueryEx** pre-check (skip PAGE_NOACCESS / PAGE_GUARD) |
| **VAC hooks** | Bypass before inject, restore immediately after | Bypass before inject, **2 s delay**, then restore on a **detached thread** |
| **Supported games** | cs2.exe, csgo.exe, RustClient.exe, gmod.exe | Same |
| **Special path** | skeet.dll (custom alloc + LoadLibrary) | Unchanged (skeet path kept) |
| **Version** | 1.5 | **2.0** |

## Features

- **ManualMap** injection (x64) – no LoadLibrary traces in the target for normal DLLs
- **NT APIs** for allocate / write / protect
- **NtCreateThreadEx** preferred for remote threads
- PE header wipe after map (with VirtualQueryEx safety check)
- VAC hook bypass + **delayed, async restore**
- Process by name or PID
- Optional Steam companion DLL injection (`steam_<cheat>.dll`)
- Color console output
- Admin privilege detection

## Requirements

- Windows OS (x64)
- Visual Studio 2017 or later
- Target process must be **64-bit** for ManualMap

## Building the Project

1. Clone the repository.
2. Open `SufnInjector.sln` (or the existing solution) in Visual Studio.
3. Build **x64** Release (or Debug).
4. Output: `SufnInjector_x64.exe` (or your configured name).

## Usage

### Automatic process detection

```sh
SufnInjector_x64.exe <dll_path>
```

Waits for a supported game (`cs2.exe`, `csgo.exe`, `RustClient.exe`, `gmod.exe`), then injects.

### Manual process selection

```sh
SufnInjector_x64.exe <process_name_or_PID> <dll_path>
```

Examples:

```sh
SufnInjector_x64.exe rakhus.dll
SufnInjector_x64.exe cs2.exe rakhus.dll
SufnInjector_x64.exe 12345 rakhus.dll
```

### Expected console flow (ManualMap)

```
[+] Injector is running with administrator privileges.
Process found: cs2.exe
[+] VAC hooks bypassed.
Attempting to inject DLL: rakhus.dll into process: cs2.exe
[+] DLL file found.
[*] Using ManualMap injection (x64)...
[*] ManualMap: ImageSize = 0x...
[+] Target memory allocated at 0x...
[+] Sections written.
[+] Shellcode written (... bytes).
[+] ManualMap thread created via NtCreateThreadEx.
[+] ManualMap succeeded. Module base: 0x...
[+] PE headers wiped successfully (... bytes).
DLL rakhus.dll injected successfully into cs2.exe via ManualMap.
[*] Waiting 2 seconds before restoring VAC hooks...
[+] VAC hooks restored.
```

## Notes

- **skeet.dll** still uses the old special path (fixed addresses + LoadLibrary).
- ManualMap is used for every other DLL.
- Run as **Administrator** when possible (full process access).
- Online use can lead to VAC / game bans — use at your own risk.
