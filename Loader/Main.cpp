#include <Windows.h>
#include <stdexcept>

typedef DWORD ( __stdcall* lpfnRtlRemoteCall )( __in HANDLE hProcess, __in HANDLE hThread, __in PVOID pvEntry, __in ULONG nArgs, __in PULONG pParameters, __in BOOLEAN bPassContext, __in BOOLEAN bSuspended );
lpfnRtlRemoteCall _RtlRemoteCall = NULL;

STARTUPINFO siStartupInfo = { NULL };
PROCESS_INFORMATION piProcessInformation = { NULL };

struct RemoteArgs
{
	LPVOID lpvLoadLibrary;
	LPVOID lpvGetProcAddress;
	LPVOID pvDllPath;
	LPVOID lpvNtContinue;
} pRemoteArgs = { NULL };

/* Change this to your MapleStory path */
LPCSTR lpszMaplePath = "C:\\Program Files (x86)\\NEXON\\Europe MapleStory\\MapleStory.exe";

/*
	The library loader uses a special loading routine which makes use of a small asm shellcode stub and the Nt API
	RtlRemoteCall to relocate the EIP of the suspended main MapleStory thread. When MapleStory's execution is continued
	the first thing it does is load the library into memory by calling the external LoadLibraryEx and then returns to
	regular execution via jumping to the previous thread context.
*/
INT CALLBACK WinMain ( __in HINSTANCE hInstance, __in HINSTANCE hPrevInstance, __in LPSTR lpCmdLine, __in INT nCmdShow )
{
	auto ReportError = [](LPCSTR lpszError)
	{
		MessageBox ( NULL, lpszError, "Error", MB_OK | MB_SYSTEMMODAL );
		abort();
	};

	if (! CreateProcess(lpszMaplePath, NULL, 0, 0, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, 0, 0, &siStartupInfo, &piProcessInformation) )
		ReportError ( "CreateProcess failed." );

	CHAR pDllPathBuffer[MAX_PATH];
	
	if (! GetCurrentDirectory(MAX_PATH, pDllPathBuffer) )
		ReportError ( "Failed to retrieve library directory." );

	if (! (sprintf_s(pDllPathBuffer, MAX_PATH, "%s\\Loadee.dll", pDllPathBuffer) >= 0) )
		ReportError ( "Failed to format library path." );

	DWORD dwPathBufferLen = strlen(pDllPathBuffer) + 1;

	HANDLE hProcess = NULL;

	if (! (hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, piProcessInformation.dwProcessId)) )
		ReportError ( "OpenProcess failed (run as administrator)." );

	LPVOID lpvRemoteDllPathBuffer;

	if (! (lpvRemoteDllPathBuffer = VirtualAllocEx(hProcess, NULL, dwPathBufferLen, MEM_COMMIT, PAGE_READWRITE)) )
		ReportError ( "Failed to allocate memory for the remote file path buffer." );

	if (! WriteProcessMemory(hProcess, lpvRemoteDllPathBuffer, pDllPathBuffer, dwPathBufferLen, NULL) )
		ReportError ( "Failed to copy the library path from the local process into the remote process." );

	pRemoteArgs.pvDllPath = lpvRemoteDllPathBuffer;

	HMODULE lpvKern32 = GetModuleHandle ( "kernelbase" );
	if (! lpvKern32 ) lpvKern32 = GetModuleHandle ( "kernel32" );

	pRemoteArgs.lpvLoadLibrary = GetProcAddress ( lpvKern32, "LoadLibraryExA" );

	if (! pRemoteArgs.lpvLoadLibrary )
		ReportError ( "Failed to locate statically loaded LoadLibraryExA." );

	pRemoteArgs.lpvGetProcAddress = GetProcAddress ( lpvKern32, "GetProcAddress" );

	if (! pRemoteArgs.lpvGetProcAddress )
		ReportError ( "Failed to locate statically loaded GetProcAddress." );
	
	HMODULE lpvNtDll = GetModuleHandle ( "ntdll" );

	if (! (_RtlRemoteCall = reinterpret_cast<lpfnRtlRemoteCall>( GetProcAddress(lpvNtDll, "RtlRemoteCall"))) )
		ReportError ( "Failed to locate RtlRemoteCall." );

	pRemoteArgs.lpvNtContinue = GetProcAddress(lpvNtDll, "NtContinue");

	if (! pRemoteArgs.lpvNtContinue )
		ReportError ( "Failed to locate statically loaded NtContinue." );

	DWORD_PTR dwpShellcodeStart, dwpShellcodeEnd;
	DWORD dwShellcodeSize;

	__asm
	{
		mov dwpShellcodeStart, offset l_ShellStart
		mov dwpShellcodeEnd, offset l_ShellEnd
		jmp l_ShellEnd
l_ShellStart:
		mov ebx, esp
		push 1
		push 0
		push [ebx+12]
		call dword ptr [ebx+4] // LoadLibraryEx
		push 11 // -- ordinal
		push eax // -- module
		call dword ptr [ebx+8] // GetProcAddress
		call dword ptr [eax] // InitClient
		push 0
		push dword ptr [ebx]
		call dword ptr [ebx+16]	// NtContinue
l_ShellEnd:
	}

	PVOID lpvRemoteShellcode;
	dwShellcodeSize = dwpShellcodeEnd - dwpShellcodeStart;

	if (! (lpvRemoteShellcode = VirtualAllocEx(hProcess, NULL, dwShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		ReportError ( "Failed to allocate memory for the remote shellcode stub." );

	if (! WriteProcessMemory(hProcess, lpvRemoteShellcode, reinterpret_cast<PVOID>(dwpShellcodeStart), dwShellcodeSize, NULL) )
		ReportError ( "Failed to copy the shellcode stub into the remote process." );

	if ( _RtlRemoteCall(piProcessInformation.hProcess, piProcessInformation.hThread, lpvRemoteShellcode, 4, reinterpret_cast<PULONG>(&pRemoteArgs), TRUE, TRUE) )
		ReportError ( "Failed to change the remote threads context." );

	ResumeThread ( piProcessInformation.hThread );
}