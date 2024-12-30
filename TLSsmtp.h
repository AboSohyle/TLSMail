#pragma once

#include <windows.h>

typedef struct _SmtpServerInfo
{
    CHAR ServerName[64];
    USHORT ServerPort;
    BOOL UseProxy;
    CHAR ProxyName[64];
    USHORT ProxyPort;
    CHAR UserAccount[64];
    CHAR Password[64];
    BOOL SecureConnection;
} SmtpServerInfo, *PSmtpServerInfo;

typedef struct _EmailInfo
{
    CHAR SendTo[64];
    CHAR Subject[32];
    CHAR Body[1024];
} EmailInfo, *PEmailInfo;

BOOL SendMail(HWND hwnd, PSmtpServerInfo smtp, PEmailInfo email);