// SRPSEStubs.c — stubs for server-side / desktop-only Cedar symbols that are
// referenced by the client-core objects we link, but never executed on iOS:
//   - UnixVLan* (TAP device management; our PACKET_ADAPTER replaces it)
//   - WgsGetProtoImpl (WireGuard protocol impl; Proto_WireGuard.c is excluded)
//   - GetAuthTypeStr / GetHubTypeStr (vpncmd/WebUI string helpers)
//   - ParseHostPort (defined in the excluded Command.c, used by Wpc.c)

#include "Cedar/Cedar.h"
#include "Cedar/Proto.h"
#include "Cedar/VLanUnix.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <string.h>

const PROTO_IMPL *WgsGetProtoImpl() { return NULL; }

wchar_t *GetAuthTypeStr(UINT id) { (void)id; return L"unknown"; }
wchar_t *GetHubTypeStr(UINT type) { (void)type; return L"unknown"; }

// Minimal host[:port] parser, compatible with the Command.c original.
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port)
{
    char *colon;
    if (src == NULL || host == NULL || port == NULL) return false;
    colon = strrchr(src, ':');
    if (colon != NULL && strchr(colon + 1, ':') == NULL && strlen(colon + 1) > 0)
    {
        *colon = 0;
        *host = src;
        *port = ToInt(colon + 1);
        if (*port == 0 || *port > 65535) return false;
    }
    else
    {
        *host = src;
        *port = default_port;
    }
    return StrLen(*host) > 0;
}

// --- UnixVLan (TAP) stubs -----------------------------------------------------

void UnixVLanInit() {}
void UnixVLanFree() {}
int  UnixVLanGet(char *name) { (void)name; return -1; }
bool UnixVLanCreate(char *name, UCHAR *mac_address, bool create_up)
{ (void)name; (void)mac_address; (void)create_up; return false; }
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{ (void)name; (void)prefix; (void)mac_address; (void)create_up; return false; }
bool UnixVLanSetState(char *name, bool state_up)
{ (void)name; (void)state_up; return true; }
void UnixVLanDelete(char *name) { (void)name; }
TOKEN_LIST *UnixVLanEnum() { return NULL; }
