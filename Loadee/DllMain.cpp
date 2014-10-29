#include <Windows.h>

/*
	If this is TRUE, the exports have a lightweight check to make sure they do not execute. Against all odds,
	if someone finds a way to get it into the process without executing DllMain and for whatever reason DllMain
	blocks (ie: breakpoint on termination, loading via manual image mapping) the exports will fail.
*/
static BOOL bIllegalInitialization = FALSE;

/*
	Export a version specific hash which can be checked by the launcher based on a one-way hashed
	encrypted version supplied by the authentication server. If the module fails to export the correct
	hash data, it is automatically unloaded. Loosely prevents IPC spoofing like David performed w/ dinput8.
*/
__declspec(dllexport) CCHAR Hash[64] =
{
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
}; // not implemented yet

/*
	We use a type definition for the call to abort so that it is stored in a local variable rather than
	being directly visible in IDA and hence not added to the functions reference list.
*/
typedef void (__cdecl* lpfnAbort)();
static lpfnAbort _abort = abort;

/*
	The real entry point for MapleStory when the library is loaded using the official launcher.
*/
__declspec(dllexport) void InitClient ( void )
{
	if ( bIllegalInitialization )
		abort();

	MessageBox ( NULL, TEXT("Client Initialized"), TEXT("Library Call"), MB_OK | MB_SYSTEMMODAL );
}

/*
	The real entry point for the Lancher UI when the library is loaded using the official launcher.
*/
__declspec(dllexport) void InitHost ( void )
{
	if ( bIllegalInitialization )
		abort();

	MessageBox ( NULL, TEXT("Host Initialized"), TEXT("Library Call"), MB_OK | MB_SYSTEMMODAL );
}

/*
	When DllMain is called the library has been injected normally without the shellcode, as one/only
	way to prevent DllMain from being called is to use LoadLibraryEx with the DONT_RESOLVE_DLL_REFERENCES
	flag rather than LoadLibrary. The problem with doing this is that LoadLibraryEx takes three arguments
	whereas CreateRemoteThread only allows for one parameter to be passed, thus, it is impossible without
	a shellcode stub.
*/
BOOL WINAPI DllMain ( __in HINSTANCE hinstDLL, __in DWORD fdwReason, __in LPVOID lpvReserved )
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	atexit(_abort);

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		bIllegalInitialization++;
		MessageBox ( NULL, TEXT("Invalid Loading Method"), TEXT("DllMain"), MB_OK | MB_SYSTEMMODAL );
	}

	return FALSE;
}