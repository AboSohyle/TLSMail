#ifdef UNICODE
#undef UNICODE
#endif
#ifdef _UNICODE
#undef _UNICODE
#endif
#include "TLSsmtp.h"

#define SECURITY_WIN32

#include <winsock.h>
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>

#include <stdio.h>

#define IO_BUFFER_SIZE 0x10000

HCERTSTORE MyCertStore = NULL;
SCHANNEL_CRED SchannelCred;
CredHandle hClientCreds;
CtxtHandle hContext;
SecBuffer ExtraData;
SOCKET TLSSocket = INVALID_SOCKET;
PSecurityFunctionTableA SSPI = NULL;
/****************************************************************************************/

const char *line = "________________________________________________________________________\n";
FILE *logfile = NULL;

/*****************************************************************************/

void WriteLog(LPCSTR message, ...)
{
    char buffer[32];
    if (logfile)
    {
        SYSTEMTIME lt;
        GetLocalTime(&lt);
        GetDateFormatA(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, &lt, "[dd'/'MM'/'yyy", buffer, 32);
        fputs(buffer, logfile);
        GetTimeFormatA(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, &lt, ", hh':'mm':'ss tt] : ", buffer, 32);
        fputs(buffer, logfile);
        va_list ap;
        va_start(ap, message);
        vfprintf(logfile, message, ap);
        va_end(ap);
        fputs("\n", logfile);
    }
}

INT DisplayWinSockError()
{
    INT lRslt = WSAGetLastError();
    if (lRslt)
    {
        LPSTR pszName = "Unknown error";
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                              FORMAT_MESSAGE_FROM_SYSTEM |
                              FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, lRslt, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&pszName, 0, NULL))
        {
            WriteLog("[E] %s\n", pszName);
            LocalFree(pszName);
        }
        else
            WriteLog("Unknown error code(%d)\n", lRslt);
    }

    return lRslt;
}

void GetDateTime(DWORD length, LPSTR buffer)
{
    SYSTEMTIME lt = {0};
    GetLocalTime(&lt);
    ZeroMemory(buffer, length);
    GetDateFormat(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, &lt, "ddd',' dd MMM',' yyy", buffer, length);
    DWORD len = lstrlenA(buffer);
    GetTimeFormat(LOCALE_USER_DEFAULT, LOCALE_USE_CP_ACP, &lt, " hh':'mm':'ss tt", buffer + len, length - len);
}

void PrintText(DWORD length, PCHAR buffer)
{
    for (int i = 0; i < (int)length; i++)
    {
        if (buffer[i] == 10 || buffer[i] == 13)
            fputc((int)buffer[i], logfile);
        else if (buffer[i] < 32 || /*buffer[i] > 126 ||*/ buffer[i] == '%')
            fputc('.', logfile);
        else
            fputc((int)buffer[i], logfile);
    }
}

void DisplayConnectionInfo(CtxtHandle *phContext)
{
    LONG Status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    Status = SSPI->QueryContextAttributes(phContext, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&ConnectionInfo);
    if (Status != SEC_E_OK)
    {
        fprintf(logfile, "[E] Querying connection info error (0x%lX)\n", Status);
        return;
    }

    switch (ConnectionInfo.dwProtocol)
    {
    case SP_PROT_TLS1_CLIENT:
        fputs("    Protocol: TLS1.0\n", logfile);
        break;
    case SP_PROT_TLS1_1_CLIENT:
        fputs("    Protocol: TLS1.1\n", logfile);
        break;
    case SP_PROT_TLS1_2_CLIENT:
        fputs("    Protocol: TLS1.2\n", logfile);
        break;
    case SP_PROT_TLS1_3_CLIENT:
        fputs("    Protocol: TLS1.3\n", logfile);
        break;
    case SP_PROT_SSL2_CLIENT:
        fputs("    Protocol: SSL2\n", logfile);
        break;
    case SP_PROT_SSL3_CLIENT:
        fputs("    Protocol: SSL3\n", logfile);
        break;
    default:
        fprintf(logfile, "    Protocol: 0x%lX\n", ConnectionInfo.dwProtocol);
    }

    switch (ConnectionInfo.aiCipher)
    {
    case CALG_RC4:
        fputs("    Cipher: RC4\n", logfile);
        break;
    case CALG_3DES:
        fputs("    Cipher: Triple DES\n", logfile);
        break;
    case CALG_RC2:
        fputs("    Cipher: RC2\n", logfile);
        break;
    case CALG_DES:
    case CALG_CYLINK_MEK:
        fputs("    Cipher: DES\n", logfile);
        break;
    case CALG_SKIPJACK:
        fputs("    Cipher: Skipjack\n", logfile);
        break;
    case CALG_AES_128:
        fputs("    Cipher: AES128\n", logfile);
        break;
    case CALG_AES_192:
        fputs("    Cipher: AES192\n", logfile);
        break;
    case CALG_AES_256:
        fputs("    Cipher: AES256\n", logfile);
        break;
    case CALG_SHA_256:
        fputs("    Cipher: SHA256\n", logfile);
        break;
    case CALG_SHA_384:
        fputs("    Cipher: SHA384\n", logfile);
        break;
    case CALG_SHA_512:
        fputs("    Cipher: SHA512\n", logfile);
        break;
    case CALG_ECDH:
        fputs("    Cipher: ECDH\n", logfile);
        break;
    case CALG_ECDH_EPHEM:
        fputs("    Cipher: ECDHE\n", logfile);
        break;
    case CALG_ECMQV:
        fputs("    Cipher: ECMQV\n", logfile);
        break;
    case CALG_ECDSA:
        fputs("    Cipher: ECDSA\n", logfile);
        break;
    default:
        fprintf(logfile, "    Cipher: 0x%X\n", ConnectionInfo.aiCipher);
    }

    switch (ConnectionInfo.aiHash)
    {
    case CALG_MD5:
        fputs("    Hash: MD5\n", logfile);
        break;
    case CALG_SHA:
        fputs("    Hash: SHA\n", logfile);
        break;
    case CALG_SHA_256:
        fputs("    Hash: SHA256\n", logfile);
        break;
    case CALG_SHA_384:
        fputs("    Hash: SHA384\n", logfile);
        break;
    case CALG_SHA_512:
        fputs("    Hash: SHA512\n", logfile);
        break;
    default:
        fprintf(logfile, "    Hash: 0x%X\n", ConnectionInfo.aiHash);
    }

    switch (ConnectionInfo.aiExch)
    {
    case CALG_RSA_KEYX:
    case CALG_RSA_SIGN:
        fprintf(logfile, "    Key exchange: RSA\n");
        break;
    case CALG_KEA_KEYX:
        fprintf(logfile, "    Key exchange: KEA\n");
        break;
    case CALG_DH_EPHEM:
        fprintf(logfile, "    Key exchange: DH Ephemeral\n");
        break;
    case CALG_ECDH:
        fprintf(logfile, "    Key exchange: ECDH\n");
        break;
    case CALG_ECDH_EPHEM:
        fprintf(logfile, "    Key exchange: ECDHE\n");
        break;
    case CALG_ECMQV:
        fprintf(logfile, "    Key exchange: ECMQV\n");
        break;
    case CALG_ECDSA:
        fprintf(logfile, "    Key exchange: ECDSA\n");
        break;
    default:
        fprintf(logfile, "    Key exchange: 0x%X\n", ConnectionInfo.aiExch);
    }
}

/****************************************************************************************/

BOOL TLSConnect(PSmtpServerInfo smtp, SOCKET *pSocket)
{
    SOCKET Socket;
    struct sockaddr_in sin;
    struct hostent *hp;

    Socket = socket(PF_INET, SOCK_STREAM, 0);
    if (Socket == INVALID_SOCKET)
    {
        DisplayWinSockError();
        return FALSE;
    }

    if (smtp->UseProxy)
    {
        sin.sin_family = AF_INET;
        sin.sin_port = ntohs(smtp->ProxyPort);
        if ((hp = gethostbyname(smtp->ProxyName)) == NULL)
        {
            closesocket(Socket);
            DisplayWinSockError();
            return FALSE;
        }
        else
            memcpy(&sin.sin_addr, hp->h_addr, 4);
    }
    else
    {
        sin.sin_family = AF_INET;
        sin.sin_port = htons(smtp->ServerPort);
        if ((hp = gethostbyname(smtp->ServerName)) == NULL)
        {
            closesocket(Socket);
            DisplayWinSockError();
            return FALSE;
        }
        else
            memcpy(&sin.sin_addr, hp->h_addr, 4);
    }

    if (connect(Socket, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
    {
        closesocket(Socket);
        fprintf(logfile, "[I] Connecting to %s failed\n", smtp->ServerName);
        return FALSE;
    }

    if (smtp->UseProxy)
    {
        CHAR pbMessage[200];
        DWORD cbMessage;

        wsprintfA((char *)pbMessage, "CONNECT %s:%d HTTP/1.0\r\nUser-Agent: webclient\r\n\r\n", smtp->ServerName, smtp->ServerPort);
        cbMessage = (DWORD)lstrlen(pbMessage);

        // Send message to proxy server
        if (send(Socket, pbMessage, cbMessage, 0) == SOCKET_ERROR)
        {
            closesocket(Socket);
            DisplayWinSockError();
            return FALSE;
        }

        // Receive message from proxy server
        cbMessage = recv(Socket, pbMessage, 200, 0);
        if (cbMessage == SOCKET_ERROR)
        {
            closesocket(Socket);
            DisplayWinSockError();
            return FALSE;
        }
    }
    *pSocket = Socket;
    fputs("[I] Connection established successfully\n", logfile);
    return TRUE;
}

BOOL TLSDisconnect()
{
    PCHAR pbMessage;
    DWORD dwType, dwSSPIFlags, dwSSPIOutFlags, cbMessage, cbData, Status;
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    TimeStamp tsExpiry;

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = sizeof(dwType);

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = SSPI->ApplyControlToken(&hContext, &OutBuffer);
    if (FAILED(Status))
    {
        fputs("[E] Apply control token failed\n", logfile);
        goto cleanup;
    }

    // Build an SSL close notify message.
    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                  ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    OutBuffers[0].pvBuffer = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = SSPI->InitializeSecurityContext(&hClientCreds, &hContext, NULL,
                                             dwSSPIFlags, 0, SECURITY_NATIVE_DREP, NULL, 0,
                                             &hContext, &OutBuffer, &dwSSPIOutFlags, &tsExpiry);

    if (FAILED(Status))
    {
        fputs("[E] Initialize security context failed (2)\n", logfile);
        goto cleanup;
    }

    pbMessage = (PCHAR)OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;

    // Send the close notify message to the server.
    if (pbMessage != NULL && cbMessage != 0)
    {
        cbData = send(TLSSocket, pbMessage, cbMessage, 0);
        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            Status = DisplayWinSockError();
            fputs("[E] Sending close notify failed\n", logfile);
            goto cleanup;
        }
        SSPI->FreeContextBuffer(pbMessage); // Free output buffer.
    }
    fputs("[I] Colsing connection succeeded\n", logfile);
cleanup:
    // SSPI->DeleteSecurityContext(&hContext); // Free the security context.
    closesocket(TLSSocket);
    TLSSocket = INVALID_SOCKET;
    return Status ? FALSE : TRUE;
}

BOOL CreateCredentials()
{
    // Open the "MY" certificate store, where IE stores client certificates.
    // Windows maintains 4 stores -- MY, CA, ROOT, SPC.
    if (MyCertStore == NULL)
    {
        MyCertStore = CertOpenSystemStore(0, "MY");
        if (!MyCertStore)
        {
            fputs("[E] returned by CertOpenSystemStore\n", logfile);
            return FALSE;
        }
    }

    // Build Schannel credential structure. Currently, this sample only
    // specifies the protocol to be used (and optionally the certificate,
    // of course). Real applications may wish to specify other parameters as well.
    ZeroMemory(&SchannelCred, sizeof(SCHANNEL_CRED));

    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_X | SP_PROT_SSL2 | SP_PROT_SSL3;
    SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

    // Create an SSPI credential.
    LONG scRet = SSPI->AcquireCredentialsHandleA(NULL,                 // Name of principal
                                                 UNISP_NAME_A,         // Name of package
                                                 SECPKG_CRED_OUTBOUND, // Flags indicating use
                                                 NULL,                 // Pointer to logon ID
                                                 &SchannelCred,        // Package specific data
                                                 NULL,                 // Pointer to GetKey() func
                                                 NULL,                 // Value to pass to GetKey()
                                                 &hClientCreds,        // (out) Cred Handle
                                                 NULL);                // (out) Lifetime (optional)

    return scRet ? FALSE : TRUE;
}

void GetNewCredentials()
{
    CredHandle hCreds;
    SecPkgContext_IssuerListInfoEx IssuerListInfo;
    PCCERT_CHAIN_CONTEXT pChainContext;
    CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
    PCCERT_CONTEXT pCertContext;
    TimeStamp tsExpiry;
    LONG Status;

    // Read list of trusted issuers from schannel.
    Status = SSPI->QueryContextAttributes(&hContext, SECPKG_ATTR_ISSUER_LIST_EX, (PVOID)&IssuerListInfo);
    if (Status != SEC_E_OK)
    {
        fputs("[E] querying issuer list info\n", logfile);
        return;
    }

    // Enumerate the client certificates.
    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

    pChainContext = NULL;

    while (TRUE)
    {
        pChainContext = CertFindChainInStore(MyCertStore, X509_ASN_ENCODING, 0, CERT_CHAIN_FIND_BY_ISSUER, &FindByIssuerPara, pChainContext);
        if (pChainContext == NULL)
        {
            fputs("[E] finding cert chain failed\n", logfile);
            break;
        }

        fputs("[I] Certificate chain found\n", logfile);

        // Get pointer to leaf certificate context.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Create schannel credential.
        SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
        SchannelCred.cCreds = 1;
        SchannelCred.paCred = &pCertContext;

        Status = SSPI->AcquireCredentialsHandle(NULL,                 // Name of principal
                                                UNISP_NAME_A,         // Name of package
                                                SECPKG_CRED_OUTBOUND, // Flags indicating use
                                                NULL,                 // Pointer to logon ID
                                                &SchannelCred,        // Package specific data
                                                NULL,                 // Pointer to GetKey() func
                                                NULL,                 // Value to pass to GetKey()
                                                &hCreds,              // (out) Cred Handle
                                                &tsExpiry);           // (out) Lifetime (optional)

        if (Status != SEC_E_OK)
        {
            fputs("[E] Acquire credentials handle returned an error\n", logfile);
            continue;
        }

        fputs("[I] New schannel credential created\n", logfile);
        SSPI->FreeCredentialsHandle(&hClientCreds); // Destroy the old credentials.
        hClientCreds = hCreds;
    }
}

BOOL HandshakeLoop(BOOL fDoInitialRead)
{
    SecBufferDesc OutBuffer, InBuffer;
    SecBuffer InBuffers[2], OutBuffers[1];
    DWORD dwSSPIFlags, dwSSPIOutFlags, cbData, cbIoBuffer;
    TimeStamp tsExpiry;
    LONG scRet;
    PCHAR IoBuffer;
    BOOL fDoRead;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                  ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    // Allocate data buffer.
    IoBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IO_BUFFER_SIZE);
    if (IoBuffer == NULL)
    {
        fputs("[E] Out of memory (1)\n", logfile);
        return FALSE;
    }
    cbIoBuffer = 0;
    fDoRead = fDoInitialRead;

    // Loop until the handshake is finished or an error occurs.
    scRet = SEC_I_CONTINUE_NEEDED;

    while (scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_E_INCOMPLETE_MESSAGE || scRet == SEC_I_INCOMPLETE_CREDENTIALS)
    {
        if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE) // Read data from server.
        {
            if (fDoRead)
            {
                cbData = recv(TLSSocket, IoBuffer + cbIoBuffer, IO_BUFFER_SIZE - cbIoBuffer, 0);
                if (cbData == SOCKET_ERROR)
                {
                    fputs("[E] reading data from server\n", logfile);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if (cbData == 0)
                {
                    fputs("[E] Server unexpectedly disconnected\n", logfile);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                cbIoBuffer += cbData;
            }
            else
                fDoRead = TRUE;
        }

        InBuffers[0].pvBuffer = IoBuffer;
        InBuffers[0].cbBuffer = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer = NULL;
        InBuffers[1].cbBuffer = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers = 2;
        InBuffer.pBuffers = InBuffers;
        InBuffer.ulVersion = SECBUFFER_VERSION;

        OutBuffers[0].pvBuffer = NULL;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = 0;

        OutBuffer.cBuffers = 1;
        OutBuffer.pBuffers = OutBuffers;
        OutBuffer.ulVersion = SECBUFFER_VERSION;

        // Call InitializeSecurityContext.
        scRet = SSPI->InitializeSecurityContext(&hClientCreds, &hContext, NULL, dwSSPIFlags,
                                                0, SECURITY_NATIVE_DREP, &InBuffer, 0, NULL,
                                                &OutBuffer, &dwSSPIOutFlags, &tsExpiry);

        if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED || (FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
        {
            if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                cbData = send(TLSSocket, (LPCSTR)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
                if (cbData == SOCKET_ERROR || cbData == 0)
                {
                    fputs("[E] sending data to server (2)\n", logfile);
                    SSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                    SSPI->DeleteSecurityContext(&hContext);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                //  Free output buffer.
                SSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }

        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        if (scRet == SEC_E_INCOMPLETE_MESSAGE)
            continue;

        // If InitializeSecurityContext returned SEC_E_OK, then the
        // handshake completed successfully.
        if (scRet == SEC_E_OK)
        {
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            fputs("[I] Handshake was successful\n", logfile);
            DisplayConnectionInfo(&hContext);
            if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                ExtraData.pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, InBuffers[1].cbBuffer);
                if (ExtraData.pvBuffer == NULL)
                {
                    fputs("[E] Out of memory (2)\n", logfile);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                MoveMemory(ExtraData.pvBuffer, IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);
                ExtraData.cbBuffer = InBuffers[1].cbBuffer;
                ExtraData.BufferType = SECBUFFER_TOKEN;
            }
            else
            {
                ExtraData.pvBuffer = NULL;
                ExtraData.cbBuffer = 0;
                ExtraData.BufferType = SECBUFFER_EMPTY;
            }
            break; // Bail out to quit
        }

        // Check for fatal error.
        if (FAILED(scRet))
        {
            fputs("[E] returned by InitializeSecurityContext (2)\n", logfile);
            break;
        }

        if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            GetNewCredentials();

            fDoRead = FALSE;
            scRet = SEC_I_CONTINUE_NEEDED;
            continue;
        }

        // Copy any leftover data from the "extra" buffer, and go around again.
        if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(IoBuffer, IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);
            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
            cbIoBuffer = 0;
    }

    // Delete the security context in the case of a fatal error.
    if (FAILED(scRet))
        SSPI->DeleteSecurityContext(&hContext);

    HeapFree(GetProcessHeap(), 0, IoBuffer);

    return scRet ? FALSE : TRUE;
}

BOOL PerformHandshake(LPSTR pszServerName)
{
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    DWORD dwSSPIFlags, dwSSPIOutFlags, cbData;
    TimeStamp tsExpiry;
    LONG scRet;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                  ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    //  Initiate a ClientHello message and generate a token.
    OutBuffers[0].pvBuffer = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = SSPI->InitializeSecurityContext(&hClientCreds, NULL, pszServerName, dwSSPIFlags,
                                            0, SECURITY_NATIVE_DREP, NULL, 0, &hContext,
                                            &OutBuffer, &dwSSPIOutFlags, &tsExpiry);

    if (scRet != SEC_I_CONTINUE_NEEDED)
    {
        fputs("[E] Initialize security context error\n", logfile);
        return FALSE;
    }

    // Send response to server if there is one.
    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        cbData = send(TLSSocket, (LPCSTR)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
        if (cbData == SOCKET_ERROR || cbData == 0)
        {
            fputs("[E] Sending data to server failed (1)\n", logfile);
            SSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
            SSPI->DeleteSecurityContext(&hContext);
            return SEC_E_INTERNAL_ERROR;
        }
        SSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }

    return HandshakeLoop(TRUE);
}

/*****************************************************************************/
int TraslateReply(LPCCH buff)
{
    char res[4] = {0};
    strncpy(res, buff, 3);
    int i = atoi(res);
    switch (i)
    {
    case 211:
    case 214:
        fputs("[I] System status message or help reply\n", logfile);
        break;
    case 220:
        fputs("[I] Server is ready\n", logfile);
        break;
    case 221:
        fputs("[I] Server is closing its transmission channel\n", logfile);
        break;
    case 235:
        fputs("[I] Server authentication succeeded\n", logfile);
        break;
    case 250:
        fputs("[I] Server replies OK\n", logfile);
        break;
    case 252:
        fputs("[W] Server cannot verify the user, but it will try to deliver the message anyway\n", logfile);
        break;
    case 354:
        fputs("[I] Server asks for DATA\n", logfile);
        break;
    case 334:
        fputs("[I] Server asks for password\n", logfile);
        break;
    case 101:
        fputs("[E] Server was unable to connect\n", logfile);
        break;
    case 111:
        fputs("[E] Connection refused or inability to open an SMTP stream\n", logfile);
        break;
    case 420:
        fputs("[E] Timeout connection problem\n", logfile);
        break;
    case 421:
        fputs("[E] The service is unavailable due to a connection problem\n", logfile);
        break;
    case 422:
        fputs("[E] The recipient\'s mailbox has exceeded its storage limit\n", logfile);
        break;
    case 431:
        fputs("[E] Not enough space on the disk, or an out-of-memory condition due to a file overload\n", logfile);
        break;
    case 441:
        fputs("[E] The recipient\'s server is not responding\n", logfile);
        break;
    case 442:
        fputs("[E] The connection was dropped during the transmission\n", logfile);
        break;
    case 446:
        fputs("[E] The maximum hop count was exceeded for the message: an internal loop has occurred\n", logfile);
        break;
    case 447:
        fputs("[E] Your outgoing message timed out because of issues concerning the incoming server\n", logfile);
        break;
    case 450:
        fputs("[E] Requested action not taken - The user\'s mailbox is unavailable\n", logfile);
        break;
    case 451:
        fputs("[E] Requested action aborted - Local ISP error in processing\n", logfile);
        break;
    case 452:
        fputs("[E] Too many emails sent or too many recipients: server storage limit exceeded\n", logfile);
        break;
    case 471:
    case 541:
        fputs("[E] The recipient address rejected your message: normally caused by an anti-spam filter\n", logfile);
        break;
    case 500:
    case 501:
        fputs("[E] A syntax error: the server couldn\'t recognize the command\n", logfile);
        break;
    case 502:
        fputs("[E] The command is not implemented\n", logfile);
        break;
    case 503:
        fputs("[E] The server has encountered a bad sequence of commands\n", logfile);
        break;
    case 504:
        fputs("[E] A command parameter is not implemented\n", logfile);
        break;
    case 251:
    case 510:
    case 511:
    case 513:
        fputs("[E] Bad email address or recipient\n", logfile);
        break;
    case 512:
        fputs("[E] A DNS error: the host server for the recipient\'s domain name cannot be found\n", logfile);
        break;
    case 523:
        fputs("[E] The total size of your mailing exceeds the recipient server\'s limits\n", logfile);
        break;
    case 530:
        fputs("[E] An authentication problem. or the recipient\'s server blacklisting yours\n", logfile);
        break;
    case 535:
        fputs("[E] Username and Password not accepted\n", logfile);
        break;
    case 550:
        fputs("[E] A non-existent email address on the remote side\n", logfile);
        break;
    case 551:
        fputs("[E] User not local or invalid address - Relay denied\n", logfile);
        break;
    case 552:
        fputs("[E] Requested mail actions aborted - Exceeded storage allocation\n", logfile);
        break;
    case 553:
        fputs("[E] Requested action not taken - Mailbox name invalid\n", logfile);
        break;
    case 554:
        fputs("[E] This means that the transaction has failed\n", logfile);
        break;
    }
    return i;
}

LONG SendAndGetResponse(PCHAR pbIoBuffer, SecPkgContext_StreamSizes Sizes)
{
    LONG scRet;
    SecBufferDesc Message;
    SecBuffer Buffers[4];
    DWORD cbMessage, cbData;
    PCHAR pbMessage = pbIoBuffer + Sizes.cbHeader;

    cbMessage = (DWORD)strlen(pbMessage);
    if (!cbMessage)
        goto READ;

    PrintText(4, "[C] ");
    PrintText(cbMessage, pbMessage);

    //  Encrypt the HTTP request.
    Buffers[0].pvBuffer = pbIoBuffer;                // Pointer to buffer 1
    Buffers[0].cbBuffer = Sizes.cbHeader;            // length of header
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER; // Type of the buffer

    Buffers[1].pvBuffer = pbMessage;        // Pointer to buffer 2
    Buffers[1].cbBuffer = cbMessage;        // length of the message
    Buffers[1].BufferType = SECBUFFER_DATA; // Type of the buffer

    Buffers[2].pvBuffer = pbMessage + cbMessage;      // Pointer to buffer 3
    Buffers[2].cbBuffer = Sizes.cbTrailer;            // length of the trailor
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER; // Type of the buffer

    Buffers[3].pvBuffer = SECBUFFER_EMPTY;   // Pointer to buffer 4
    Buffers[3].cbBuffer = SECBUFFER_EMPTY;   // length of buffer 4
    Buffers[3].BufferType = SECBUFFER_EMPTY; // Type of the buffer 4

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;
    scRet = SSPI->EncryptMessage(&hContext, 0, &Message, 0);
    if (FAILED(scRet))
    {
        fputs("[E] returned by EncryptMessage\n", logfile);
        return scRet;
    }

    cbData = send(TLSSocket, pbIoBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);

    if (cbData == SOCKET_ERROR || cbData == 0)
    {
        fputs("[E] sending data to server (3)\n", logfile);
        return SEC_E_INTERNAL_ERROR;
    }
READ:
    DWORD cbIoBufferLength = Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
    DWORD cbIoBuffer = 0;
    while (TRUE)
    {
        if (cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE) // get the data
        {
            cbData = recv(TLSSocket, pbIoBuffer + cbIoBuffer, cbIoBufferLength - cbIoBuffer, 0);
            if (cbData == SOCKET_ERROR)
            {
                fputs("[E] reading data from server\n", logfile);
                return SEC_E_INTERNAL_ERROR;
            }
            else if (cbData == 0)
            {
                if (cbIoBuffer)
                {
                    fputs("[E] Server unexpectedly disconnected\n", logfile);
                    return SEC_E_INTERNAL_ERROR;
                }
                else
                    break; // All Done
            }
            else // success
            {
                cbIoBuffer += cbData;
            }
        }
        // Decrypt the received data.
        Buffers[0].pvBuffer = pbIoBuffer;
        Buffers[0].cbBuffer = cbIoBuffer;
        Buffers[0].BufferType = SECBUFFER_DATA;  // Initial Type of the buffer 1
        Buffers[1].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 2
        Buffers[2].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 3
        Buffers[3].BufferType = SECBUFFER_EMPTY; // Initial Type of the buffer 4

        Message.ulVersion = SECBUFFER_VERSION; // Version number
        Message.cBuffers = 4;                  // Number of buffers - must contain four SecBuffer structures.
        Message.pBuffers = Buffers;            // Pointer to array of buffers
        scRet = SSPI->DecryptMessage(&hContext, &Message, 0, NULL);

        if (scRet == SEC_I_CONTEXT_EXPIRED)
        {
            fputs("[I] Server signalled end of session\n", logfile);
            return scRet;
        }

        if (scRet != SEC_E_OK && scRet != SEC_I_RENEGOTIATE && scRet != SEC_I_CONTEXT_EXPIRED)
        {
            fputs("[E] Decrypting Message\n", logfile);
            return scRet;
        }

        // Locate data and (optional) extra buffers.
        SecBuffer *pDataBuffer = NULL, *pExtraBuffer = NULL;

        for (int i = 1; i < 4; i++)
        {
            if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
                pDataBuffer = &Buffers[i];
            if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
                pExtraBuffer = &Buffers[i];
        }

        // Display the decrypted data.
        if (pDataBuffer)
        {
            if (pDataBuffer->cbBuffer)
            {
                PCHAR buff = (PCHAR)pDataBuffer->pvBuffer;
                PrintText(4, "[S] ");
                PrintText(pDataBuffer->cbBuffer, buff);
                int rep = TraslateReply(buff);
                if ((rep > 100 && rep < 112) || rep > 419)
                    return SEC_E_INTERNAL_ERROR;
                if (buff[pDataBuffer->cbBuffer - 2] == 13 && buff[pDataBuffer->cbBuffer - 1] == 10)
                    break;
            }
        }
        // Move any "extra" data to the input buffer.
        if (pExtraBuffer)
        {
            MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            cbIoBuffer = pExtraBuffer->cbBuffer;
        }
        else
            cbIoBuffer = 0;

        // The server wants to perform another handshake sequence.
        if (scRet == SEC_I_RENEGOTIATE)
        {
            fputs("[I] Server requested renegotiate!\n", logfile);
            scRet = HandshakeLoop(FALSE);
            if (scRet != SEC_E_OK)
                return scRet;

            if (ExtraData.pvBuffer) // Move any "extra" data to the input buffer.
            {
                MoveMemory(pbIoBuffer, ExtraData.pvBuffer, ExtraData.cbBuffer);
                cbIoBuffer = ExtraData.cbBuffer;
            }
        }
    }

    return SEC_E_OK;
}

/*****************************************************************************/

BOOL SMTPsession(PSmtpServerInfo smtp, PEmailInfo email)
{
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS scRet;
    PCHAR pbIoBuffer, IoBufferPtr, out64;
    CHAR buffer[32];
    DWORD outlen, inlen;

    scRet = SSPI->QueryContextAttributes(&hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (scRet != SEC_E_OK)
    {
        fputs("[E] Reading SECPKG_ATTR_STREAM_SIZES failed\n", logfile);
        return FALSE;
    }

    inlen = Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
    pbIoBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, inlen);
    if (pbIoBuffer == NULL)
    {
        fputs("[E] Out of memory (2)\n", logfile);
        return FALSE;
    }
    IoBufferPtr = pbIoBuffer + Sizes.cbHeader;

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    /******************************EHLO********************************/
    gethostname(buffer, 32);
    wsprintfA(IoBufferPtr, "EHLO %s\r\n", buffer);

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    /****************AUTH LOGIN*****user64********pass64*********************/
    CryptBinaryToStringA((LPCBYTE)smtp->UserAccount, strlen(smtp->UserAccount), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outlen);
    out64 = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outlen);
    CryptBinaryToStringA((LPCBYTE)smtp->UserAccount, strlen(smtp->UserAccount), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out64, &outlen);
    wsprintfA(IoBufferPtr, "AUTH LOGIN %s\r\n", out64);
    HeapFree(GetProcessHeap(), 0, out64);

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    CryptBinaryToStringA((LPCBYTE)smtp->Password, strlen(smtp->Password), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outlen);
    out64 = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outlen);
    CryptBinaryToStringA((LPCBYTE)smtp->Password, strlen(smtp->Password), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out64, &outlen);
    wsprintfA(IoBufferPtr, "%s\r\n", out64);
    HeapFree(GetProcessHeap(), 0, out64);

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    /***************************MAIL FROM:<%s>************************/

    wsprintfA(IoBufferPtr, "MAIL FROM: <%s>\r\n", smtp->UserAccount);
    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    /***************************RCPT TO:<%s>************************/

    wsprintfA(IoBufferPtr, "RCPT TO: <%s>\r\n", email->SendTo);
    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    /***************************DATA************************/

    wsprintfA(IoBufferPtr, "DATA\r\n");

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;

    /***************************content************************/
    GetDateTime(32, buffer);
    wsprintfA(IoBufferPtr, "Date: %s\r\n"
                           "From: %s\r\n"
                           "To: %s\r\n"
                           "Subject: %s\r\n"
                           "MIME-Version: 1.0\r\n"
                           "Content-Type: text/plain; charset=UTF-8\r\n"
                           "Content-Transfer-Encoding: QUOTED-PRINTABLE\r\n"
                           "X-Mailer: MailClient v1.0 by Wael Mohammed Ali\r\n"
                           "%s"
                           "\r\n.\r\n",
              buffer, smtp->UserAccount, email->SendTo, email->Subject, email->Body);

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);
    if (scRet != SEC_E_OK)
        goto cleanup;
    /*************************QUIT*******************************/
    wsprintfA(IoBufferPtr, "QUIT\r\n");

    scRet = SendAndGetResponse(pbIoBuffer, Sizes);

cleanup:
    HeapFree(GetProcessHeap(), 0, pbIoBuffer);
    if (scRet)
        fputs("[E] Session internal error has occured\n", logfile);
    return scRet ? FALSE : TRUE;
}

/*****************************************************************************/

BOOL SendMail(HWND hwnd, PSmtpServerInfo smtp, PEmailInfo email)
{
    HMODULE dll = LoadLibraryA("Secur32.dll");
    if (dll == NULL)
    {
        MessageBox(hwnd, "Security library not loaded!", "Mail", MB_ICONERROR);
        return FALSE;
    }

    WSADATA WsaData;
    char buf[128] = {0};
    BOOL Error = TRUE;
    logfile = fopen("session.log", "a");
    // fseek(logfile, 0, SEEK_END);
    // DWORD len = ftell(logfile);
    // if (len > 10240)
    // {
    //     fclose(logfile);
    //     DeleteFile("session.log");
    //     logfile = fopen("session.log", "a");
    // }
    // fseek(logfile, 0, SEEK_SET);
    // fputs("\n[I] Starting session ", logfile);
    // GetDateTime(128, buf);
    // fputs(buf, logfile);
    // fputs("\n", logfile);

    if (SOCKET_ERROR != WSAStartup(0x0101, &WsaData))
    {
        if (TLSConnect(smtp, &TLSSocket))
        {
            if (CreateCredentials())
            {
                if (PerformHandshake(smtp->ServerName))
                {
                    Error = !SMTPsession(smtp, email);
                    TLSDisconnect();
                    SSPI->DeleteSecurityContext(&hContext);
                }
                SSPI->FreeCredentialsHandle(&hClientCreds);
            }
        }
        WSACleanup();
    }
    else
        DisplayWinSockError();

    if (MyCertStore)
        CertCloseStore(MyCertStore, 0);

    FreeLibrary(dll);

    if (logfile)
    {
        fputs("[I] Session ends ", logfile);
        GetDateTime(128, buf);
        fputs(buf, logfile);
        fputs("\n", logfile);
        fputs(line, logfile);
        fclose(logfile);
        logfile = 0;
    }

    if (Error)
        MessageBox(hwnd, "Something went wrong view log for more informations", "Mail", MB_ICONERROR);
    else
        MessageBox(hwnd, "Message sent successfully.", email->Subject, MB_ICONINFORMATION);

    return !Error;
}
