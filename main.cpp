#ifndef UNICODE
#define UNICODE 1
#endif

#ifndef _UNICODE
#define _UNICODE 1
#endif

#define _WIN32_WINNT _WIN32_WINNT_WIN10
#define _WIN32_IE _WIN32_IE_IE100

#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN

#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>
#include <wininet.h>
#include "resource.h"
#include "TLSsmtp.h"

#define LogFile L"session.log"
#define WM_ALLDONE (WM_USER + 1)
#define WM_VIEWLOG (WM_USER + 2)
#define FileExists(a) (BOOL)(GetFileAttributes(a) != 0xFFFFFFFF)

CONST POINT Pt = {12, 40};
HWND Page1, Page2, Page3, Page4;
HANDLE thread;

#define ShowTabPage(a)                                                               \
    {                                                                                \
        SetWindowPos(a, NULL, 0, 0, 0, 0, SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOMOVE); \
        SetFocus(a);                                                                 \
    }

#define HideTabPage(a) SetWindowPos(a, NULL, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOSIZE | SWP_NOMOVE)

typedef struct threaddata
{
    SmtpServerInfo smtp;
    EmailInfo mail;
    HWND hwndDlg;
} TData, *PTData;

VOID GetMultiByteChar(HWND hwndDlg, UINT id, CHAR *out, UINT len)
{
    HWND ctrl = GetDlgItem(hwndDlg, id);
    DWORD dwTextLength = GetWindowTextLength(ctrl);
    if (dwTextLength > 0)
    {
        dwTextLength = (dwTextLength + 1) * sizeof(WCHAR);
        LPWCH buffer = (LPWCH)GlobalAlloc(GPTR, dwTextLength);
        if (buffer != NULL)
        {
            if (GetWindowText(ctrl, buffer, dwTextLength))
            {
                WideCharToMultiByte(CP_UTF8, 0, buffer, -1, out, len, 0, 0);
            }
            GlobalFree(buffer);
        }
    }
}

DWORD WINAPI SendProc(LPVOID lParam)
{
    PTData data = (PTData)lParam;
    int idx = TabCtrl_GetCurSel(GetDlgItem(data->hwndDlg, IDC_TAB));
    EnableWindow(GetDlgItem(data->hwndDlg, IDC_TAB), FALSE);
    UINT i;
    switch (idx)
    {
    case 0:
        for (i = IDC_SERVERNAME; i < IDC_SENDTOME; i++)
            EnableWindow(GetDlgItem(Page1, i), FALSE);
        break;
    case 1:
        for (i = IDC_SENDTOME; i < IDC_EDITLOG; i++)
            EnableWindow(GetDlgItem(Page2, i), FALSE);
        break;
    }
    EnableWindow(GetDlgItem(data->hwndDlg, IDC_SEND), FALSE);
    EnableWindow(GetDlgItem(data->hwndDlg, IDC_CANCEL), FALSE);

    BOOL ret = SendMail(data->hwndDlg, &(data->smtp), &(data->mail));

    EnableWindow(GetDlgItem(data->hwndDlg, IDC_TAB), TRUE);
    switch (idx)
    {
    case 0:
        for (i = IDC_SERVERNAME; i < IDC_SENDTOME; i++)
        {
            if (i == IDC_PROXYNAME && !IsDlgButtonChecked(Page1, IDC_USEPROXY))
                i += 2;
            EnableWindow(GetDlgItem(Page1, i), TRUE);
        }
        break;
    case 1:
        for (i = IDC_SENDTOME; i < IDC_EDITLOG; i++)
        {
            if (i == IDC_MSGSENDTO && IsDlgButtonChecked(Page2, IDC_SENDTOME))
                i += 1;
            EnableWindow(GetDlgItem(Page2, i), TRUE);
        }
        break;
    }
    EnableWindow(GetDlgItem(data->hwndDlg, IDC_SEND), TRUE);
    EnableWindow(GetDlgItem(data->hwndDlg, IDC_CANCEL), TRUE);

    SendMessage(data->hwndDlg, WM_ALLDONE, 0, (LPARAM)lParam);
    return ret;
}

VOID ValidateInput(HWND hwndDlg)
{
    UINT a, b, c, d, e, f, g, h, i, j, port;
    a = Edit_GetTextLength(GetDlgItem(Page1, IDC_SERVERNAME)) ? 1 : 0;
    port = GetDlgItemInt(Page1, IDC_SERVERPORT, 0, 0);
    b = (port && port < 65536) ? 1 : 0;
    h = IsDlgButtonChecked(Page1, IDC_USEPROXY);
    if (h)
    {
        i = Edit_GetTextLength(GetDlgItem(Page1, IDC_PROXYNAME)) ? 1 : 0;
        port = GetDlgItemInt(Page1, IDC_PROXYPORT, 0, 0);
        j = (port && port < 65536) ? 1 : 0;
    }
    c = Edit_GetTextLength(GetDlgItem(Page1, IDC_USERNAME)) ? 1 : 0;
    d = Edit_GetTextLength(GetDlgItem(Page1, IDC_USERPASSWORD)) ? 1 : 0;
    if (IsDlgButtonChecked(Page2, IDC_SENDTOME))
        e = 1;
    else
        e = Edit_GetTextLength(GetDlgItem(Page2, IDC_MSGSENDTO)) ? 1 : 0;

    f = Edit_GetTextLength(GetDlgItem(Page2, IDC_MSGSUBJECT)) ? 1 : 0;
    g = Edit_GetTextLength(GetDlgItem(Page2, IDC_MSGCONTENT)) ? 1 : 0;
    if (h)
    {
        if (a && b && c && d && e && f && g && i && j)
            Button_Enable(GetDlgItem(hwndDlg, IDC_SEND), TRUE);
        else
            Button_Enable(GetDlgItem(hwndDlg, IDC_SEND), FALSE);
    }
    else
    {
        if (a && b && c && d && e && f && g)
            Button_Enable(GetDlgItem(hwndDlg, IDC_SEND), TRUE);
        else
            Button_Enable(GetDlgItem(hwndDlg, IDC_SEND), FALSE);
    }
}

static INT_PTR CALLBACK PageProc(HWND hwndPge, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HWND ctrl;
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        Edit_LimitText(GetDlgItem(hwndPge, IDC_PROXYPORT), 5);
        Edit_LimitText(GetDlgItem(hwndPge, IDC_SERVERPORT), 5);
        Edit_LimitText(GetDlgItem(hwndPge, IDC_MSGCONTENT), 1023);
        // Edit_SetCueBannerText
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_SERVERNAME), L"smtp server name");
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_SERVERPORT), L"465 etc.");
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_USERNAME), L"you@mail.box");
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_USERPASSWORD), L"your password");
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_MSGSENDTO), L"someone@mail.box");
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_MSGSUBJECT), L"Title");
        Edit_SetCueBannerText(GetDlgItem(hwndPge, IDC_MSGCONTENT), L"your message...");
        return TRUE;
    }
    case WM_VIEWLOG:
    {
        if (!FileExists(LogFile))
            Edit_SetText(GetDlgItem(hwndPge, IDC_EDITLOG), L"Empty\r\n");
        else
        {
            HANDLE hFile = CreateFile(LogFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD len = GetFileSize(hFile, 0);
                PCHAR buffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
                if (ReadFile(hFile, buffer, len, 0, 0))
                {
                    DWORD utf16len = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, NULL, 0);
                    LPWSTR text = (LPWSTR)malloc(utf16len * sizeof(WCHAR));
                    MultiByteToWideChar(CP_UTF8, 0, buffer, -1, text, utf16len);
                    SetWindowText(GetDlgItem(hwndPge, IDC_EDITLOG), text);
                    free(text);
                }
                HeapFree(GetProcessHeap(), 0, buffer);
                CloseHandle(hFile);
            }
        }
        return TRUE;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_SERVERNAME:
        case IDC_SERVERPORT:
        case IDC_PROXYNAME:
        case IDC_PROXYPORT:
        case IDC_USERNAME:
        case IDC_USERPASSWORD:
        case IDC_MSGSENDTO:
        case IDC_MSGSUBJECT:
        case IDC_MSGCONTENT:
        {
            if (HIWORD(wParam) == EN_CHANGE)
            {
                ValidateInput(GetParent(hwndPge));
                return TRUE;
            }
            break;
        }
        case IDC_USEPROXY:
        {
            ctrl = (HWND)lParam;
            if (Button_GetCheck(ctrl) == BST_CHECKED)
            {
                ctrl = GetDlgItem(hwndPge, IDC_PROXYNAME);
                Edit_Enable(ctrl, TRUE);
                Edit_Enable(GetDlgItem(hwndPge, IDC_PROXYPORT), TRUE);
                SetFocus(ctrl);
            }
            else
            {
                SetFocus(GetNextDlgTabItem(hwndPge, ctrl, TRUE));
                Edit_Enable(GetDlgItem(hwndPge, IDC_PROXYNAME), FALSE);
                Edit_Enable(GetDlgItem(hwndPge, IDC_PROXYPORT), FALSE);
            }
            ValidateInput(GetParent(hwndPge));
            return TRUE;
        }
        case IDC_SENDTOME:
        {
            ctrl = (HWND)lParam;
            if (Button_GetCheck(ctrl) == BST_CHECKED)
            {
                ctrl = GetDlgItem(hwndPge, IDC_MSGSENDTO);
                Edit_Enable(GetDlgItem(hwndPge, IDC_MSGSENDTO), FALSE);
                SetFocus(GetNextDlgTabItem(hwndPge, ctrl, FALSE));
            }
            else
            {
                ctrl = GetDlgItem(hwndPge, IDC_MSGSENDTO);
                Edit_Enable(ctrl, TRUE);
                SetFocus(ctrl);
            }
            ValidateInput(GetParent(hwndPge));
            return TRUE;
        }
        case IDC_SHOWPW:
        {
            ctrl = GetDlgItem(hwndPge, IDC_USERPASSWORD);
            if (Button_GetCheck((HWND)lParam) == BST_CHECKED)
                Edit_SetPasswordChar(ctrl, 0);
            else
                SendMessage(ctrl, EM_SETPASSWORDCHAR, 0x25cf, 0);
            SetFocus(ctrl);
            return TRUE;
        }
        }
        break;
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    {
        // if (Page4 == hwndPge)
        //     break;
        return (INT_PTR)(HBRUSH)GetStockObject(WHITE_BRUSH);
    }
    }
    return FALSE;
}

static INT_PTR CALLBACK MainDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        TCITEM tie;
        tie.mask = TCIF_TEXT | TCIF_IMAGE;
        tie.iImage = -1;
        tie.pszText = L"Server Setup";
        HWND ctrl = GetDlgItem(hwndDlg, IDC_TAB);
        TabCtrl_InsertItem(ctrl, 0, &tie);
        tie.pszText = L"Mail Details";
        TabCtrl_InsertItem(ctrl, 1, &tie);
        tie.pszText = L"View Log";
        TabCtrl_InsertItem(ctrl, 2, &tie);
        tie.pszText = L"About";
        TabCtrl_InsertItem(ctrl, 3, &tie);

        TabCtrl_SetCurSel(ctrl, 0);

        HINSTANCE hInst = GetModuleHandle(0);
        Page1 = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PAGE1), hwndDlg, (DLGPROC)PageProc);
        Page2 = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PAGE2), hwndDlg, (DLGPROC)PageProc);
        Page3 = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PAGE3), hwndDlg, (DLGPROC)PageProc);
        Page4 = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PAGE4), hwndDlg, (DLGPROC)PageProc);

        SetWindowPos(Page1, NULL, Pt.x, Pt.y, 0, 0, SWP_SHOWWINDOW | SWP_NOSIZE);
        SetWindowPos(Page2, NULL, Pt.x, Pt.y, 0, 0, SWP_HIDEWINDOW | SWP_NOSIZE);
        SetWindowPos(Page3, NULL, Pt.x, Pt.y, 0, 0, SWP_HIDEWINDOW | SWP_NOSIZE);
        SetWindowPos(Page4, NULL, Pt.x, Pt.y, 0, 0, SWP_HIDEWINDOW | SWP_NOSIZE);
        SendMessage(Page3, WM_VIEWLOG, 0, 0);

        return TRUE;
    }
    case WM_NOTIFY:
    {
        INT iSel;
        switch (((LPNMHDR)lParam)->code)
        {
        case TCN_SELCHANGING:
            iSel = TabCtrl_GetCurSel(((LPNMHDR)lParam)->hwndFrom);
            if (iSel == 0)
                HideTabPage(Page1);
            else if (iSel == 1)
                HideTabPage(Page2);
            else if (iSel == 2)
                HideTabPage(Page3);
            else if (iSel == 3)
                HideTabPage(Page4);
            return TRUE;
        case TCN_SELCHANGE:
            iSel = TabCtrl_GetCurSel(((LPNMHDR)lParam)->hwndFrom);
            if (iSel == 0)
            {
                ShowTabPage(Page1);
            }
            else if (iSel == 1)
            {
                ShowTabPage(Page2);
            }
            else if (iSel == 2)
            {
                ShowTabPage(Page3);
            }
            else if (iSel == 3)
            {
                ShowTabPage(Page4);
            }
            break;
        }
        return TRUE;
    }
    case WM_ALLDONE:
    {
        CloseHandle(thread);
        HeapFree(GetProcessHeap(), 0, (LPVOID)lParam);
        SendMessage(Page3, WM_VIEWLOG, 0, 0);
        HWND ctrl = GetDlgItem(hwndDlg, IDC_TAB);
        INT iSel = TabCtrl_GetCurSel(ctrl);
        if (iSel == 0)
            SetWindowPos(Page1, NULL, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
        else if (iSel == 1)
            SetWindowPos(Page2, NULL, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
        else if (iSel == 4)
            SetWindowPos(Page4, NULL, 0, 0, 0, 0, SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
        TabCtrl_SetCurSel(ctrl, 2);
        SetWindowPos(Page3, NULL, Pt.x, Pt.y, 0, 0, SWP_SHOWWINDOW | SWP_NOSIZE | SWP_NOZORDER);
        SetFocus(Page3);
        return TRUE;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_CANCEL:
        {
            return !EndDialog(hwndDlg, 0);
        }
        case IDC_SEND:
        {
            PTData mal = (PTData)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TData));

            GetMultiByteChar(Page1, IDC_SERVERNAME, mal->smtp.ServerName, 64);
            mal->smtp.ServerPort = GetDlgItemInt(Page1, IDC_SERVERPORT, NULL, FALSE);
            if (IsDlgButtonChecked(Page1, IDC_USEPROXY))
            {
                mal->smtp.UseProxy = TRUE;
                GetMultiByteChar(Page1, IDC_PROXYNAME, mal->smtp.ProxyName, 64);
                mal->smtp.ProxyPort = GetDlgItemInt(Page1, IDC_PROXYPORT, NULL, FALSE);
            }
            GetMultiByteChar(Page1, IDC_USERNAME, mal->smtp.UserAccount, 64);
            GetMultiByteChar(Page1, IDC_USERPASSWORD, mal->smtp.Password, 64);

            if (IsDlgButtonChecked(Page2, IDC_SENDTOME))
                strcpy(mal->mail.SendTo, mal->smtp.UserAccount);
            else
                GetMultiByteChar(Page2, IDC_MSGSENDTO, mal->mail.SendTo, 64);
            GetMultiByteChar(Page2, IDC_MSGSUBJECT, mal->mail.Subject, 32);
            GetMultiByteChar(Page2, IDC_MSGCONTENT, mal->mail.Body, 1024);

            mal->hwndDlg = hwndDlg;
            thread = CreateThread(NULL, 0, SendProc, mal, 0, 0);
            return TRUE;
        }
        }
        break;
    }
    case WM_CLOSE:
        return !EndDialog(hwndDlg, 0);
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int)
{
    INITCOMMONCONTROLSEX icc = {};
    WNDCLASSEX wcx = {};

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    wcx.cbSize = sizeof(wcx);
    if (!GetClassInfoEx(NULL, MAKEINTRESOURCE(32770), &wcx))
        return 0;

    wcx.hInstance = hInstance;
    wcx.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPICON));
    wcx.lpszClassName = L"MailClientClass";
    if (!RegisterClassEx(&wcx))
        return 0;

    return (int)DialogBox(hInstance, MAKEINTRESOURCE(IDD_APPMAIN), NULL, (DLGPROC)MainDlgProc);
}
