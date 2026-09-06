// SPDX-License-Identifier: MIT
// =============================================================================
//  xways-xml-viewer — a *Viewer* X-Tension for X-Ways Forensics 21.7+ (C++/x64)
//
//  Two ways to look at an XML file, one DLL:
//
//    * LIVE (default): an Edge WebView2 control parented onto the viewer
//      component's preview window (XWF_GetWindow(0,6), class "SCCVIEWER") shows
//      a collapsible tree, an XPath 1.0 query box (browser-native DOMParser +
//      document.evaluate — no third-party JS), query history and a render
//      cap. XT_View returns a 1-byte NUL buffer so the stock viewer draws
//      nothing. The page (ui/viewer.html) is embedded as RCDATA.
//    * BASIC: static, colour-coded, indented HTML returned as UTF-16 for the
//      viewer component to draw. Used for the whole session when the cfg says
//      `mode=basic` or no WebView2 Runtime is installed. The live page's
//      "Basic" tab renders the same view.
//
//  The mode is decided once in XT_Init and never mixed within a session: a text
//  buffer returned while X-Ways has no viewer window leaves the pane in text
//  view, which hides a WebView attached on a later call (X-Ways 21.8).
//
//  The WebView2 host (pane attach/retry/heartbeat/z-order, security settings,
//  cfg sidecar) is shared with xways-json-viewer. X-Ways 21.8 behaviour this
//  code depends on:
//    * returned HTML honours CSS but never runs <script>;
//    * index 6 is NULL on the first call of a session and after re-selecting
//      the same item or switching modes; X-Ways destroys and recreates that
//      window, so every call re-reads it and checks the cached one with IsWindow;
//    * when index 6 is NULL the returned buffer is shown as plain TEXT;
//    * XT_ReleaseMem fires on the *next* selection, not right after the call;
//    * case reports do not call XT_View (default report settings);
//    * with "Activate separate viewer component" off there is never a pane.
//
//  Official API reference: https://www.x-ways.net/forensics/x-tensions/api.html
//  Viewer entry points:    https://www.x-ways.net/forensics/x-tensions/XT_functions.html#viewer
// =============================================================================

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wrl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
#include "WebView2.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

// --- Identity ---------------------------------------------------------------
static const wchar_t* NAME         = L"xways-xml-viewer";
static const wchar_t* VERSION      = L"0.3.0-beta";
static const wchar_t* DESCRIPTION  = L"Viewer X-Tension: live XPath tree view of XML in the preview pane (WebView2), with a basic colour-coded mode";
static const wchar_t* REPORT_TABLE = L"Xml-Viewer Findings";   // unused by a viewer; kept for convention

// --- Logging verbosity ------------------------------------------------------
static constexpr bool VERBOSE = false;
// Optional diagnostics: dump the pane's child windows with each host-state log.
static constexpr bool kDumpChildren = false;

// --- Limits -----------------------------------------------------------------
// XT_View runs synchronously on X-Ways' UI thread: bound the work.
static constexpr INT64 kDefaultCapBytes = 8 * 1024 * 1024;    // render cap default
static constexpr INT64 kMaxCapBytes     = 512LL * 1024 * 1024; // hard ceiling for the cfg value
static INT64 g_capBytes = kDefaultCapBytes;                    // adjustable in the page, persisted
static constexpr UINT  kRetryTimerId   = 1;
static constexpr UINT  kBeatTimerId    = 2;
static constexpr UINT  kBeatPeriodMs   = 250;   // keeps bounds + z-order right: SCCVIEWER forwards no WM_SIZE
static constexpr size_t kHistoryMax    = 50;
static constexpr UINT  kRetryPeriodMs  = 100;
static constexpr int   kRetryMaxTicks  = 20;     // 2 s of polling for a late pane

// --- Mode -------------------------------------------------------------------
static bool g_cfgBasic = false;   // cfg `mode=basic` — analyst opt-out of the live view
static bool g_hosted   = true;    // decided once in XT_Init: live (WebView2) or basic (static HTML)

// --- Function-pointer typedefs (names/types mirror X-Tension.h) --------------
typedef VOID   (__stdcall *pfn_XWF_OutputMessage)(const wchar_t* msg, DWORD nFlags);
typedef const wchar_t* (__stdcall *pfn_XWF_GetItemName)(LONG nItemID);
typedef INT64  (__stdcall *pfn_XWF_GetItemSize)(LONG nItemID);
typedef INT64  (__stdcall *pfn_XWF_GetSize)(HANDLE hVolumeOrItem, LPVOID lpOptional);
typedef DWORD  (__stdcall *pfn_XWF_Read)(HANDLE hVolumeOrItem, INT64 nOffset, BYTE* lpBuffer, DWORD nNumberOfBytesToRead);
typedef LONG   (__stdcall *pfn_XWF_GetItemType)(LONG nItemID, wchar_t* lpTypeDescr, DWORD nBufferLenAndFlags);
typedef HWND   (__stdcall *pfn_XWF_GetWindow)(WORD nWndNo, WORD nWndIndex);

static pfn_XWF_OutputMessage XWF_OutputMessage = nullptr;
static pfn_XWF_GetItemName   XWF_GetItemName   = nullptr;
static pfn_XWF_GetItemSize   XWF_GetItemSize   = nullptr;
static pfn_XWF_GetSize       XWF_GetSize       = nullptr;
static pfn_XWF_Read          XWF_Read          = nullptr;
static pfn_XWF_GetItemType   XWF_GetItemType   = nullptr;
static pfn_XWF_GetWindow     XWF_GetWindow     = nullptr;

// XWF_GetItemType: low WORD = buffer length in wchar_t, bit 29 = type description.
static constexpr DWORD kItemTypeDescr = 0x20000000;

// --- State ------------------------------------------------------------------
static HMODULE g_hSelf     = nullptr;
static HWND    g_hMainWnd  = nullptr;
static std::atomic<long> g_viewCalls{0};
static std::atomic<long> g_releaseCalls{0};
static bool    g_comInitedHere = false;

// WebView2 host
static ComPtr<ICoreWebView2Environment> g_env;
static ComPtr<ICoreWebView2Controller>  g_ctrl;
static ComPtr<ICoreWebView2>            g_web;
static HWND         g_hPane        = nullptr;   // pane the controller is parented to
static bool         g_envCreating  = false;
static bool         g_ctrlCreating = false;
static bool         g_pageReady    = false;     // page posted "ready"
static std::wstring g_pendingEnvelope;          // document waiting for the page
static std::wstring g_pageHtml;                 // loaded once from resources
struct HistEntry { std::wstring file, query; };
static std::vector<HistEntry> g_history;        // most recent first, persisted in cfg
static RECT         g_lastFit      = {0};
static HWND         g_hMsgWnd      = nullptr;   // message-only window for the timers
static int          g_retryTicks   = 0;
static bool         g_itemLive     = false;     // our last claimed buffer not yet released
static bool         g_hidden       = true;

// --- Logging ----------------------------------------------------------------
static void Log(const std::wstring& msg) {
    std::wstring line = L"["; line += NAME; line += L"] "; line += msg;
    if (XWF_OutputMessage) XWF_OutputMessage(line.c_str(), 0);
}
static void Logf(const wchar_t* fmt, ...) {
    wchar_t b[1024];
    va_list ap; va_start(ap, fmt); _vsnwprintf_s(b, _TRUNCATE, fmt, ap); va_end(ap);
    Log(b);
}
static void LogVerbosef(const wchar_t* fmt, ...) {
    if (!VERBOSE) return;
    wchar_t b[1024];
    va_list ap; va_start(ap, fmt); _vsnwprintf_s(b, _TRUNCATE, fmt, ap); va_end(ap);
    Log(b);
}

template <typename T>
static T Resolve(HMODULE h, const char* name, int& missing) {
    T p = reinterpret_cast<T>(GetProcAddress(h, name));
    if (!p) ++missing;
    return p;
}

static int RetrieveFunctionPointers() {
    HMODULE h = GetModuleHandleW(nullptr);
    int missing = 0;
    XWF_OutputMessage = Resolve<pfn_XWF_OutputMessage>(h, "XWF_OutputMessage", missing);
    XWF_GetItemName   = Resolve<pfn_XWF_GetItemName  >(h, "XWF_GetItemName",   missing);
    XWF_GetItemSize   = Resolve<pfn_XWF_GetItemSize  >(h, "XWF_GetItemSize",   missing);
    XWF_GetSize       = Resolve<pfn_XWF_GetSize      >(h, "XWF_GetSize",       missing);
    XWF_Read          = Resolve<pfn_XWF_Read         >(h, "XWF_Read",          missing);
    XWF_GetItemType   = Resolve<pfn_XWF_GetItemType  >(h, "XWF_GetItemType",   missing);
    XWF_GetWindow     = Resolve<pfn_XWF_GetWindow    >(h, "XWF_GetWindow",     missing);
    return missing;
}

// =============================================================================
//  Small utilities
// =============================================================================
static std::wstring ToLower(std::wstring s) { for (auto& c : s) c = (wchar_t)towlower(c); return s; }

static std::wstring DescribePane(HWND h) {
    if (!h || !IsWindow(h)) return L"NULL";
    RECT rc = {0}; GetWindowRect(h, &rc);
    wchar_t b[160];
    swprintf_s(b, L"0x%p vis=%d rect=%ldx%ld@%ld,%ld", (void*)h, IsWindowVisible(h) ? 1 : 0, rc.right - rc.left, rc.bottom - rc.top, rc.left, rc.top);
    return b;
}

static std::wstring DllDir() {
    wchar_t p[MAX_PATH] = {0};
    GetModuleFileNameW(g_hSelf, p, MAX_PATH);
    std::wstring s = p;
    size_t k = s.find_last_of(L"\\/");
    return k == std::wstring::npos ? L"." : s.substr(0, k);
}

static std::wstring CfgPath() { return DllDir() + L"\\" + NAME + L".cfg"; }

static std::wstring Utf8ToW(const char* p, int n) {
    if (n <= 0) return {};
    int w = MultiByteToWideChar(CP_UTF8, 0, p, n, nullptr, 0);
    std::wstring s(w, L'\0');
    if (w) MultiByteToWideChar(CP_UTF8, 0, p, n, &s[0], w);
    return s;
}
static std::string WToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string o(n, '\0');
    if (n) WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &o[0], n, nullptr, nullptr);
    return o;
}

// cfg sidecar next to the DLL: mode=live|basic, cap_bytes=<n>, history=<file>\t<query>.
static void LoadCfg() {
    HANDLE h = CreateFileW(CfgPath().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(h, nullptr), got = 0;
    std::string raw(sz, '\0');
    if (sz) ReadFile(h, &raw[0], sz, &got, nullptr);
    CloseHandle(h);
    std::wstring text = Utf8ToW(raw.data(), (int)got);
    size_t pos = 0;
    while (pos < text.size()) {
        size_t e = text.find(L'\n', pos);
        std::wstring line = text.substr(pos, e == std::wstring::npos ? std::wstring::npos : e - pos);
        pos = e == std::wstring::npos ? text.size() : e + 1;
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' ')) line.pop_back();
        if (line.rfind(L"mode=", 0) == 0) {
            g_cfgBasic = (ToLower(line.substr(5)) == L"basic");
        }
        else if (line.rfind(L"cap_bytes=", 0) == 0) {
            INT64 v = _wtoi64(line.c_str() + 10);
            if (v >= 64 * 1024 && v <= kMaxCapBytes) g_capBytes = v;
        }
        else if (line.rfind(L"history=", 0) == 0 && g_history.size() < kHistoryMax) {
            std::wstring rest = line.substr(8);
            size_t t = rest.find(L'\t');
            if (t != std::wstring::npos) g_history.push_back({rest.substr(0, t), rest.substr(t + 1)});
            else g_history.push_back({L"", rest});
        }
    }
}

static void SaveCfg() {
    std::wstring cfgText = L"# xways-xml-viewer settings (auto-written; mode=live|basic is analyst-edited, history=<file>\\t<query>)\r\n";
    cfgText += std::wstring(L"mode=") + (g_cfgBasic ? L"basic" : L"live") + L"\r\n";
    cfgText += L"cap_bytes=" + std::to_wstring(g_capBytes) + L"\r\n";
    for (auto& h : g_history) cfgText += L"history=" + h.file + L"\t" + h.query + L"\r\n";
    std::string body = WToUtf8(cfgText);
    HANDLE h = CreateFileW(CfgPath().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { Logf(L"could not write %s (gle=%lu)", CfgPath().c_str(), GetLastError()); return; }
    DWORD w = 0; WriteFile(h, body.data(), (DWORD)body.size(), &w, nullptr);
    CloseHandle(h);
    LogVerbosef(L"cfg saved to %s", CfgPath().c_str());
}

static std::wstring LoadResourceText(int id) {
    HRSRC r = FindResourceW(g_hSelf, MAKEINTRESOURCEW(id), (LPCWSTR)RT_RCDATA);
    if (!r) return {};
    HGLOBAL g = LoadResource(g_hSelf, r);
    if (!g) return {};
    const char* p = (const char*)LockResource(g);
    DWORD n = SizeofResource(g_hSelf, r);
    if (n >= 3 && (BYTE)p[0] == 0xEF && (BYTE)p[1] == 0xBB && (BYTE)p[2] == 0xBF) { p += 3; n -= 3; }
    return Utf8ToW(p, (int)n);
}

// JSON string escaping for the envelope (UTF-16 in → JSON text out).
static void AppendJsonString(std::wstring& o, const std::wstring& s) {
    o += L'"';
    for (wchar_t c : s) {
        switch (c) {
            case L'"':  o += L"\\\""; break;
            case L'\\': o += L"\\\\"; break;
            case L'\n': o += L"\\n";  break;
            case L'\r': o += L"\\r";  break;
            case L'\t': o += L"\\t";  break;
            default:
                if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                    wchar_t b[8]; swprintf_s(b, L"\\u%04x", (unsigned)c); o += b;
                } else o += c;
        }
    }
    o += L'"';
}

// =============================================================================
//  Type gate
// =============================================================================
static bool HasXmlExtension(const std::wstring& lowerName) {
    static const wchar_t* kExts[] = {
        L".xml", L".plist", L".svg", L".manifest", L".xaml", L".xsd", L".xsl", L".xslt",
        L".rdf", L".rss", L".atom", L".kml", L".gpx", L".xcu", L".xcs", L".resx",
        L".csproj", L".vcxproj", L".props", L".targets", L".nuspec", L".config",
        L".rels", L".dtd", L".wsdl", L".xhtml", L".opml", L".mxml", L".dita", L".xib", L".storyboard",
    };
    for (auto e : kExts) {
        size_t n = wcslen(e);
        if (lowerName.size() >= n && lowerName.compare(lowerName.size() - n, n, e) == 0) return true;
    }
    return false;
}

// Content sniff for text-typed items: after an optional BOM and whitespace, XML starts
// with '<' followed by '?', '!' or a name-start character. Handles UTF-16 LE and BE.
static bool SniffLooksXml(HANDLE hItem) {
    if (!XWF_Read) return false;
    BYTE head[128] = {0};
    DWORD got = XWF_Read(hItem, 0, head, sizeof(head));
    if (got == 0) return false;
    size_t i = 0; int stride = 1, hi = 0;   // hi = offset of the low byte within a UTF-16 unit
    if (got >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF) i = 3;
    else if (got >= 2 && head[0] == 0xFF && head[1] == 0xFE) { i = 2; stride = 2; hi = 0; }
    else if (got >= 2 && head[0] == 0xFE && head[1] == 0xFF) { i = 2; stride = 2; hi = 1; }
    else if (got >= 4 && head[0] == '<' && head[1] == 0) { stride = 2; hi = 0; }   // BOM-less UTF-16 LE
    else if (got >= 4 && head[0] == 0 && head[1] == '<') { stride = 2; hi = 1; }   // BOM-less UTF-16 BE
    for (; i + hi < got; i += stride) {
        BYTE c = head[i + hi];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c != '<') return false;
        size_t j = i + stride;
        if (j + hi >= got) return false;
        BYTE d = head[j + hi];
        return d == '?' || d == '!' || d == '_' || d == ':' || (d >= 'A' && d <= 'Z') || (d >= 'a' && d <= 'z') || d >= 0x80;
    }
    return false;
}

// Type description contains "xml", or an XML-family extension, or the bytes look like
// XML on a text-typed item. The type string alone is not a reliable gate — X-Ways reports
// an ApplicationSettings.xml as "Web configuration", for example — so the extension list
// is checked first.
static bool IsXmlItem(HANDLE hItem, LONG nItemID, std::wstring& typeDescrOut, const wchar_t** how) {
    wchar_t descr[256] = {0};
    if (XWF_GetItemType) XWF_GetItemType(nItemID, descr, kItemTypeDescr | (DWORD)(sizeof(descr) / sizeof(descr[0])));
    typeDescrOut = descr;
    const wchar_t* nm = XWF_GetItemName ? XWF_GetItemName(nItemID) : nullptr;
    if (nm && HasXmlExtension(ToLower(nm))) { *how = L"ext"; return true; }
    std::wstring ld = ToLower(typeDescrOut);
    if (ld.find(L"xml") != std::wstring::npos) { *how = L"type"; return true; }
    if (ld.empty() || ld.find(L"text") != std::wstring::npos || ld.find(L"ascii") != std::wstring::npos ||
        ld.find(L"unicode") != std::wstring::npos || ld.find(L"unknown") != std::wstring::npos) {
        if (SniffLooksXml(hItem)) { *how = L"sniff"; return true; }
    }
    *how = L"";
    return false;
}

// =============================================================================
//  Encoding sniff + decode
// =============================================================================
struct Decoded {
    std::wstring text;
    std::wstring encoding;   // human label for the header / envelope
};

static std::wstring FromCodePage(UINT cp, const char* p, int n) {
    if (n <= 0) return {};
    int len = MultiByteToWideChar(cp, 0, p, n, nullptr, 0);
    if (len <= 0) return {};
    std::wstring out((size_t)len, L'\0');
    MultiByteToWideChar(cp, 0, p, n, &out[0], len);
    return out;
}

static Decoded DecodeBytes(const std::vector<BYTE>& raw) {
    Decoded d;
    const BYTE* b = raw.data();
    size_t n = raw.size();

    if (n >= 2 && b[0] == 0xFF && b[1] == 0xFE) {                    // UTF-16 LE BOM
        d.encoding = L"UTF-16 LE (BOM)";
        d.text.assign(reinterpret_cast<const wchar_t*>(b + 2), (n - 2) / 2);
        return d;
    }
    if (n >= 2 && b[0] == 0xFE && b[1] == 0xFF) {                    // UTF-16 BE BOM
        d.encoding = L"UTF-16 BE (BOM)";
        d.text.resize((n - 2) / 2);
        for (size_t i = 0; i < d.text.size(); ++i) d.text[i] = (wchar_t)((b[2 + 2 * i] << 8) | b[3 + 2 * i]);
        return d;
    }
    if (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) {    // UTF-8 BOM
        d.encoding = L"UTF-8 (BOM)";
        d.text = FromCodePage(CP_UTF8, reinterpret_cast<const char*>(b + 3), (int)(n - 3));
        return d;
    }
    if (n >= 4 && b[0] == '<' && b[1] == 0 && b[3] == 0) {           // BOM-less UTF-16 LE
        d.encoding = L"UTF-16 LE (no BOM)";
        d.text.assign(reinterpret_cast<const wchar_t*>(b), n / 2);
        return d;
    }
    if (n >= 4 && b[0] == 0 && b[1] == '<' && b[2] == 0) {           // BOM-less UTF-16 BE
        d.encoding = L"UTF-16 BE (no BOM)";
        d.text.resize(n / 2);
        for (size_t i = 0; i < d.text.size(); ++i) d.text[i] = (wchar_t)((b[2 * i] << 8) | b[2 * i + 1]);
        return d;
    }
    // XML declaration encoding="..." for single-byte code pages that map to a Windows code page.
    {
        std::string head(reinterpret_cast<const char*>(b), n < 256 ? n : 256);
        size_t p = head.find("encoding=");
        if (p != std::string::npos && p + 10 < head.size()) {
            char q = head[p + 9];
            size_t e = head.find(q, p + 10);
            if (e != std::string::npos) {
                std::string enc = head.substr(p + 10, e - (p + 10));
                for (auto& c : enc) c = (char)tolower((unsigned char)c);
                UINT cp = 0;
                if (enc == "windows-1252" || enc == "cp1252") cp = 1252;
                else if (enc == "iso-8859-1" || enc == "latin1" || enc == "latin-1") cp = 28591;
                else if (enc == "us-ascii" || enc == "ascii") cp = 20127;
                if (cp) {
                    d.encoding = FromCodePage(CP_UTF8, enc.c_str(), (int)enc.size()) + L" (declared)";
                    d.text = FromCodePage(cp, reinterpret_cast<const char*>(b), (int)n);
                    return d;
                }
            }
        }
    }
    // Strict UTF-8, else Windows-1252.
    {
        int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(b), (int)n, nullptr, 0);
        if (len > 0 || n == 0) {
            d.encoding = L"UTF-8";
            d.text.resize((size_t)len);
            if (len) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(b), (int)n, &d.text[0], len);
            return d;
        }
    }
    d.encoding = L"Windows-1252 (invalid UTF-8)";
    d.text = FromCodePage(1252, reinterpret_cast<const char*>(b), (int)n);
    return d;
}

// =============================================================================
//  Basic mode — tolerant pretty-printer (tokenizer, not a parser) → static HTML
// =============================================================================
static void AppendEscaped(std::wstring& out, const wchar_t* s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        switch (s[i]) {
            case L'<':  out += L"&lt;";   break;
            case L'>':  out += L"&gt;";   break;
            case L'&':  out += L"&amp;";  break;
            case L'"':  out += L"&quot;"; break;
            case L'\0': out += L"␀"; break;   // visible NUL — common in carved data
            default:    out += s[i];
        }
    }
}
static void AppendEscaped(std::wstring& out, const std::wstring& s) { AppendEscaped(out, s.data(), s.size()); }

static void Indent(std::wstring& out, int depth) {
    out += L'\n';
    for (int i = 0; i < depth; ++i) out += L"  ";
}

static std::wstring TrimWs(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Emit one tag's interior (between '<' and '>') with name / attribute colouring.
static void EmitTagInterior(std::wstring& out, const std::wstring& t) {
    size_t i = 0;
    while (i < t.size() && !iswspace(t[i])) ++i;
    out += L"<span class=\"tn\">"; AppendEscaped(out, t.data(), i); out += L"</span>";
    while (i < t.size()) {
        while (i < t.size() && iswspace(t[i])) ++i;
        if (i >= t.size()) break;
        if (t[i] == L'/' || t[i] == L'?') { out += t[i]; ++i; continue; }
        size_t ns = i;
        while (i < t.size() && t[i] != L'=' && !iswspace(t[i]) && t[i] != L'/') ++i;
        out += L" <span class=\"an\">"; AppendEscaped(out, t.data() + ns, i - ns); out += L"</span>";
        while (i < t.size() && iswspace(t[i])) ++i;
        if (i < t.size() && t[i] == L'=') {
            out += L"=";
            ++i;
            while (i < t.size() && iswspace(t[i])) ++i;
            size_t vs = i;
            if (i < t.size() && (t[i] == L'"' || t[i] == L'\'')) {
                wchar_t q = t[i++];
                while (i < t.size() && t[i] != q) ++i;
                if (i < t.size()) ++i;
            } else {
                while (i < t.size() && !iswspace(t[i]) && t[i] != L'/') ++i;
            }
            out += L"<span class=\"av\">"; AppendEscaped(out, t.data() + vs, i - vs); out += L"</span>";
        }
    }
}

static void PrettyPrint(std::wstring& out, const std::wstring& x) {
    int depth = 0;
    size_t i = 0, n = x.size();
    while (i < n) {
        if (x[i] == L'<') {
            if (x.compare(i, 4, L"<!--") == 0) {
                size_t e = x.find(L"-->", i + 4);
                size_t end = (e == std::wstring::npos) ? n : e + 3;
                Indent(out, depth);
                out += L"<span class=\"cm\">"; AppendEscaped(out, x.data() + i, end - i); out += L"</span>";
                i = end; continue;
            }
            if (x.compare(i, 9, L"<![CDATA[") == 0) {
                size_t e = x.find(L"]]>", i + 9);
                size_t end = (e == std::wstring::npos) ? n : e + 3;
                Indent(out, depth);
                out += L"<span class=\"cd\">"; AppendEscaped(out, x.data() + i, end - i); out += L"</span>";
                i = end; continue;
            }
            size_t e = x.find(L'>', i + 1);
            if (e == std::wstring::npos) {   // unterminated tag (truncated file) — dump the rest as text
                Indent(out, depth);
                out += L"<span class=\"bad\">"; AppendEscaped(out, x.data() + i, n - i); out += L"</span>";
                break;
            }
            std::wstring t = x.substr(i + 1, e - i - 1);
            bool isClose = !t.empty() && t[0] == L'/';
            bool isPI    = !t.empty() && (t[0] == L'?' || t[0] == L'!');
            bool selfClose = !t.empty() && t.back() == L'/';
            if (isClose) { if (depth > 0) --depth; }
            Indent(out, depth);
            if (isPI) {
                out += L"<span class=\"pi\">&lt;"; AppendEscaped(out, t); out += L"&gt;</span>";
            } else {
                out += L"<span class=\"br\">&lt;</span>";
                EmitTagInterior(out, t);
                out += L"<span class=\"br\">&gt;</span>";
            }
            if (!isClose && !isPI && !selfClose) ++depth;
            i = e + 1;
        } else {
            size_t e = x.find(L'<', i);
            if (e == std::wstring::npos) e = n;
            std::wstring txt = TrimWs(x.substr(i, e - i));
            if (!txt.empty()) {
                Indent(out, depth);
                out += L"<span class=\"tx\">"; AppendEscaped(out, txt); out += L"</span>";
            }
            i = e;
        }
    }
}

static std::wstring BuildStaticHtml(LONG nItemID, const std::wstring& name, const std::wstring& typeDescr,
                                    INT64 fileSize, const Decoded& d, bool truncated) {
    std::wstring h;
    h.reserve(d.text.size() * 2 + 4096);
    h += L"<!DOCTYPE html><html><head><meta charset=\"utf-16\"><title>";
    AppendEscaped(h, name);
    h += L"</title><style>"
         L"body{font-family:Consolas,'Courier New',monospace;font-size:12px;margin:8px;background:#fff;color:#000}"
         L".hdr{font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#444;border-bottom:1px solid #ccc;margin-bottom:6px;padding-bottom:4px}"
         L"pre{white-space:pre-wrap;word-wrap:break-word;margin:0}"
         L".br{color:#808080}.tn{color:#800080;font-weight:bold}.an{color:#b00000}.av{color:#0000c0}"
         L".tx{color:#000}.cm{color:#008000;font-style:italic}.cd{color:#806000}.pi{color:#808080}.bad{background:#fdd}"
         L".trunc{background:#ffc;color:#900;font-weight:bold;padding:4px;margin-top:6px}"
         L"</style></head><body>";
    wchar_t meta[512];
    swprintf_s(meta, L"<div class=\"hdr\">%s %s (basic mode) &middot; item %ld &middot; type &ldquo;%s&rdquo; &middot; %lld bytes &middot; encoding %s</div>",
               NAME, VERSION, nItemID, typeDescr.empty() ? L"?" : typeDescr.c_str(), (long long)fileSize, d.encoding.c_str());
    h += meta;
    h += L"<pre>";
    PrettyPrint(h, d.text);
    h += L"</pre>";
    if (truncated) {
        wchar_t t[160];
        swprintf_s(t, L"<div class=\"trunc\">Truncated: only the first %lld bytes were rendered (cap_bytes in the cfg).</div>", (long long)g_capBytes);
        h += t;
    }
    h += L"</body></html>";
    return h;
}

// UTF-16 LE + FF FE BOM — required for the viewer component to treat the buffer as HTML.
static PVOID ReturnUtf16(const std::wstring& text, PINT64 nResSize) {
    const size_t bytes = 2 + text.size() * sizeof(wchar_t);
    BYTE* buf = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, bytes));
    if (!buf) { *nResSize = -2; return nullptr; }
    buf[0] = 0xFF; buf[1] = 0xFE;
    memcpy(buf + 2, text.data(), text.size() * sizeof(wchar_t));
    *nResSize = (INT64)bytes;
    return buf;
}

// =============================================================================
//  WebView2 host (shared with xways-json-viewer)
// =============================================================================
static void ShowWeb(bool show) {
    if (g_ctrl && g_hidden == show) { g_ctrl->put_IsVisible(show ? TRUE : FALSE); g_hidden = !show; }
}

static void FitToPane() {
    if (!g_ctrl || !g_hPane || !IsWindow(g_hPane)) return;
    RECT rc = {0}; GetClientRect(g_hPane, &rc);
    g_ctrl->put_Bounds(rc);
    g_lastFit = rc;
}

// Outside In's SCCDISPLAY child is created after ours and lands above it in z-order,
// painting over the WebView. Move our HWND back to the top.
static void RaiseWeb() {
    if (!g_hPane || !IsWindow(g_hPane)) return;
    HWND h = FindWindowExW(g_hPane, nullptr, L"Chrome_WidgetWin_0", nullptr);
    if (h) SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

static BOOL CALLBACK LogChildProc(HWND h, LPARAM) {
    wchar_t cls[64] = {0}; GetClassNameW(h, cls, 64);
    RECT rc = {0}; GetWindowRect(h, &rc);
    LogVerbosef(L"    child 0x%p \"%s\" vis=%d %ldx%ld@%ld,%ld", (void*)h, cls, IsWindowVisible(h) ? 1 : 0,
                rc.right - rc.left, rc.bottom - rc.top, rc.left, rc.top);
    return TRUE;
}

static void LogHostState(const wchar_t* when) {
    if (!VERBOSE) return;
    RECT b = {0}; if (g_ctrl) g_ctrl->get_Bounds(&b);
    BOOL vis = FALSE; if (g_ctrl) g_ctrl->get_IsVisible(&vis);
    LogVerbosef(L"  [%s] pane %s; ctrl bounds=%ldx%ld@%ld,%ld visible=%d", when, DescribePane(g_hPane).c_str(),
                b.right - b.left, b.bottom - b.top, b.left, b.top, vis ? 1 : 0);
    if (kDumpChildren && g_hPane && IsWindow(g_hPane)) EnumChildWindows(g_hPane, LogChildProc, 0);
}

static void PostEnvelopeIfReady() {
    if (g_web && g_pageReady && !g_pendingEnvelope.empty()) {
        HRESULT hr = g_web->PostWebMessageAsString(g_pendingEnvelope.c_str());
        LogVerbosef(L"  envelope posted (%llu chars) hr=0x%08lX", (unsigned long long)g_pendingEnvelope.size(), hr);
        g_pendingEnvelope.clear();
        FitToPane();
        RaiseWeb();
        LogHostState(L"after envelope");
    }
}

static LRESULT CALLBACK PaneSubclassProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR, DWORD_PTR) {
    if (m == WM_SIZE || m == WM_WINDOWPOSCHANGED || m == WM_SHOWWINDOW) { FitToPane(); RaiseWeb(); }
    else if (m == WM_NCDESTROY) RemoveWindowSubclass(h, PaneSubclassProc, 1);
    return DefSubclassProc(h, m, w, l);
}

static void DropController(const wchar_t* why) {
    if (g_ctrl) {
        LogVerbosef(L"  closing WebView2 controller (%s)", why);
        g_web.Reset();
        g_ctrl->Close();
        g_ctrl.Reset();
    }
    if (g_hPane && IsWindow(g_hPane)) RemoveWindowSubclass(g_hPane, PaneSubclassProc, 1);
    g_hPane = nullptr; g_pageReady = false; g_hidden = true;
}

static void AddHistory(const std::wstring& file, const std::wstring& q) {
    if (q.empty()) return;
    for (auto it = g_history.begin(); it != g_history.end(); ++it)
        if (it->query == q && it->file == file) { g_history.erase(it); break; }
    g_history.insert(g_history.begin(), {file, q});
    if (g_history.size() > kHistoryMax) g_history.resize(kHistoryMax);
    SaveCfg();
}

static void OnWebMessage(const std::wstring& msg) {
    size_t t = msg.find(L'\t');
    std::wstring kind = msg.substr(0, t), body = t == std::wstring::npos ? L"" : msg.substr(t + 1);
    if (kind == L"ready") { g_pageReady = true; LogVerbosef(L"  page ready"); PostEnvelopeIfReady(); }
    else if (kind == L"hist") {
        size_t t2 = body.find(L'\t');
        if (t2 != std::wstring::npos) AddHistory(body.substr(0, t2), body.substr(t2 + 1));
    }
    else if (kind == L"cap") {
        INT64 v = _wtoi64(body.c_str());
        if (v >= 64 * 1024 && v <= kMaxCapBytes) { g_capBytes = v; SaveCfg(); Logf(L"render cap set to %lld bytes (applies on the next selection)", (long long)g_capBytes); }
    }
    else if (kind == L"log") { LogVerbosef(L"  [page] %s", body.c_str()); }
}

static void CreateController(HWND pane);
static void StartBeat();

static void EnsureEnvironment(HWND pane) {
    if (g_env) { CreateController(pane); return; }
    if (g_envCreating) return;
    g_envCreating = true;
    wchar_t local[MAX_PATH] = {0};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local);
    std::wstring udf = std::wstring(local) + L"\\" + NAME + L"\\WebView2";
    SHCreateDirectoryExW(nullptr, udf.c_str(), nullptr);
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(nullptr, udf.c_str(), nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [pane](HRESULT res, ICoreWebView2Environment* env) -> HRESULT {
                g_envCreating = false;
                if (FAILED(res) || !env) { Logf(L"WebView2 environment creation failed hr=0x%08lX (is the WebView2 Runtime installed?)", res); return S_OK; }
                g_env = env;
                LPWSTR ver = nullptr;
                if (SUCCEEDED(env->get_BrowserVersionString(&ver)) && ver) { LogVerbosef(L"  WebView2 environment ready, runtime %s", ver); CoTaskMemFree(ver); }
                if (IsWindow(pane)) CreateController(pane);
                return S_OK;
            }).Get());
    if (FAILED(hr)) { g_envCreating = false; Logf(L"CreateCoreWebView2EnvironmentWithOptions failed hr=0x%08lX", hr); }
}

static void CreateController(HWND pane) {
    if (!g_env || g_ctrlCreating || !IsWindow(pane)) return;
    g_ctrlCreating = true;
    g_hPane = pane;
    SetWindowSubclass(pane, PaneSubclassProc, 1, 0);
    HRESULT hr = g_env->CreateCoreWebView2Controller(pane,
        Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
            [pane](HRESULT res, ICoreWebView2Controller* ctrl) -> HRESULT {
                g_ctrlCreating = false;
                if (FAILED(res) || !ctrl) { Logf(L"WebView2 controller creation failed hr=0x%08lX", res); return S_OK; }
                if (pane != g_hPane || !IsWindow(pane)) { ctrl->Close(); LogVerbosef(L"  controller arrived for a stale pane; discarded"); return S_OK; }
                g_ctrl = ctrl;
                g_ctrl->get_CoreWebView2(&g_web);
                ComPtr<ICoreWebView2Settings> st;
                if (g_web && SUCCEEDED(g_web->get_Settings(&st)) && st) {
                    st->put_AreDefaultContextMenusEnabled(TRUE);   // filtered below via ContextMenuRequested
                    st->put_IsStatusBarEnabled(FALSE);
                    st->put_AreDevToolsEnabled(VERBOSE ? TRUE : FALSE);
                    st->put_IsZoomControlEnabled(TRUE);
                    // Disable capabilities the page does not use.
                    st->put_AreHostObjectsAllowed(FALSE);
                    st->put_AreDefaultScriptDialogsEnabled(FALSE);
                    ComPtr<ICoreWebView2Settings4> st4;
                    if (SUCCEEDED(st.As(&st4)) && st4) {
                        st4->put_IsPasswordAutosaveEnabled(FALSE);
                        st4->put_IsGeneralAutofillEnabled(FALSE);
                    }
                }
                {
                    ComPtr<ICoreWebView2Controller4> c4;
                    if (SUCCEEDED(g_ctrl.As(&c4)) && c4) c4->put_AllowExternalDrop(FALSE);
                }
                EventRegistrationToken tok;
                // The page is NavigateToString-only (origin about:blank). Cancel any other
                // navigation and every popup.
                g_web->add_NavigationStarting(
                    Callback<ICoreWebView2NavigationStartingEventHandler>(
                        [](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* a) -> HRESULT {
                            LPWSTR uri = nullptr; a->get_Uri(&uri);
                            const bool ok = uri && (wcscmp(uri, L"about:blank") == 0 || wcsncmp(uri, L"data:", 5) == 0);
                            if (!ok) {
                                a->put_Cancel(TRUE);
                                Logf(L"blocked navigation to %s", uri ? uri : L"<null>");
                            }
                            if (uri) CoTaskMemFree(uri);
                            return S_OK;
                        }).Get(), &tok);
                g_web->add_NewWindowRequested(
                    Callback<ICoreWebView2NewWindowRequestedEventHandler>(
                        [](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* a) -> HRESULT {
                            a->put_Handled(TRUE);   // no popups / external windows
                            return S_OK;
                        }).Get(), &tok);
                g_web->add_ProcessFailed(
                    Callback<ICoreWebView2ProcessFailedEventHandler>(
                        [](ICoreWebView2*, ICoreWebView2ProcessFailedEventArgs* a) -> HRESULT {
                            COREWEBVIEW2_PROCESS_FAILED_KIND kind = COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED;
                            a->get_ProcessFailedKind(&kind);
                            Logf(L"WebView2 process failed (kind=%d) — dropping controller; next preview recreates it", (int)kind);
                            DropController(L"process failed");
                            return S_OK;
                        }).Get(), &tok);
                // Context menu: keep copy, cut, paste, select-all and print only.
                {
                    ComPtr<ICoreWebView2_11> web11;
                    if (SUCCEEDED(g_web.As(&web11)) && web11) {
                        web11->add_ContextMenuRequested(
                            Callback<ICoreWebView2ContextMenuRequestedEventHandler>(
                                [](ICoreWebView2*, ICoreWebView2ContextMenuRequestedEventArgs* args) -> HRESULT {
                                    ComPtr<ICoreWebView2ContextMenuItemCollection> items;
                                    if (FAILED(args->get_MenuItems(&items)) || !items) return S_OK;
                                    UINT n = 0; items->get_Count(&n);
                                    for (INT i = (INT)n - 1; i >= 0; --i) {
                                        ComPtr<ICoreWebView2ContextMenuItem> it;
                                        if (FAILED(items->GetValueAtIndex((UINT)i, &it)) || !it) continue;
                                        LPWSTR nm = nullptr;
                                        if (FAILED(it->get_Name(&nm)) || !nm) continue;
                                        const bool keep =
                                            wcscmp(nm, L"copy") == 0 || wcscmp(nm, L"cut") == 0 ||
                                            wcscmp(nm, L"paste") == 0 || wcscmp(nm, L"selectAll") == 0 ||
                                            wcscmp(nm, L"print") == 0 ||
                                            (VERBOSE && wcscmp(nm, L"inspectElement") == 0);
                                        CoTaskMemFree(nm);
                                        if (!keep) items->RemoveValueAtIndex((UINT)i);
                                    }
                                    return S_OK;
                                }).Get(), &tok);
                    }
                }
                g_web->add_WebMessageReceived(
                    Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                        [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* a) -> HRESULT {
                            LPWSTR s = nullptr;
                            if (SUCCEEDED(a->TryGetWebMessageAsString(&s)) && s) { OnWebMessage(s); CoTaskMemFree(s); }
                            return S_OK;
                        }).Get(), &tok);
                g_hidden = true;
                FitToPane();
                ShowWeb(true);
                StartBeat();
                g_pageReady = false;
                HRESULT nh = g_web->NavigateToString(g_pageHtml.c_str());
                LogVerbosef(L"  WebView2 controller ready on pane %s; NavigateToString hr=0x%08lX", DescribePane(pane).c_str(), nh);
                return S_OK;
            }).Get());
    if (FAILED(hr)) { g_ctrlCreating = false; Logf(L"CreateCoreWebView2Controller failed hr=0x%08lX", hr); }
}

// Attach (or re-attach) to the pane and hand over the current document.
static void AttachAndShow(HWND pane) {
    if (g_hPane && (g_hPane != pane || !IsWindow(g_hPane))) DropController(g_hPane != pane ? L"pane changed" : L"pane destroyed");
    if (g_ctrl) { FitToPane(); ShowWeb(true); RaiseWeb(); PostEnvelopeIfReady(); return; }
    EnsureEnvironment(pane);
}

// Retry timer: the pane often appears a moment after XT_View returned (first call of a
// session, after a mode switch). Poll briefly while our item is still the current one.
static void CALLBACK RetryTimerProc(HWND, UINT, UINT_PTR, DWORD) {
    if (!g_itemLive || g_pendingEnvelope.empty() || ++g_retryTicks > kRetryMaxTicks) { KillTimer(g_hMsgWnd, kRetryTimerId); return; }
    HWND pane = XWF_GetWindow ? XWF_GetWindow(0, 6) : nullptr;
    if (pane && IsWindow(pane)) {
        KillTimer(g_hMsgWnd, kRetryTimerId);
        LogVerbosef(L"  late pane %s appeared after %d tick(s) — attaching", DescribePane(pane).c_str(), g_retryTicks);
        AttachAndShow(pane);
    }
}

static void CALLBACK BeatTimerProc(HWND, UINT, UINT_PTR, DWORD) {
    if (!g_ctrl) { KillTimer(g_hMsgWnd, kBeatTimerId); return; }
    if (!g_hPane || !IsWindow(g_hPane)) { DropController(L"pane destroyed (heartbeat)"); KillTimer(g_hMsgWnd, kBeatTimerId); return; }
    if (g_hidden) return;
    RECT rc = {0}; GetClientRect(g_hPane, &rc);
    if (rc.right != g_lastFit.right || rc.bottom != g_lastFit.bottom) FitToPane();
    HWND top = GetWindow(g_hPane, GW_CHILD);
    wchar_t cls[32] = {0}; if (top) GetClassNameW(top, cls, 32);
    if (wcscmp(cls, L"Chrome_WidgetWin_0") != 0) RaiseWeb();
}

static void StartBeat() { if (g_hMsgWnd) SetTimer(g_hMsgWnd, kBeatTimerId, kBeatPeriodMs, BeatTimerProc); }

static void StartRetry() {
    if (!g_hMsgWnd) return;
    g_retryTicks = 0;
    SetTimer(g_hMsgWnd, kRetryTimerId, kRetryPeriodMs, RetryTimerProc);
}

static std::wstring BuildEnvelope(LONG nItemID, const std::wstring& name, const std::wstring& typeDescr,
                                  INT64 size, const Decoded& d, bool truncated) {
    std::wstring e; e.reserve(d.text.size() + 512);
    e += L"{\"name\":"; AppendJsonString(e, name);
    e += L",\"itemId\":" + std::to_wstring(nItemID);
    e += L",\"size\":" + std::to_wstring(size);
    e += L",\"maxBytes\":" + std::to_wstring(g_capBytes);
    e += L",\"typeDescr\":"; AppendJsonString(e, typeDescr);
    e += L",\"encoding\":"; AppendJsonString(e, d.encoding);
    e += truncated ? L",\"truncated\":true" : L",\"truncated\":false";
    e += L",\"ver\":"; AppendJsonString(e, VERSION);
    e += L",\"history\":[";
    for (size_t i = 0; i < g_history.size(); ++i) {
        if (i) e += L",";
        e += L"{\"f\":"; AppendJsonString(e, g_history[i].file);
        e += L",\"q\":"; AppendJsonString(e, g_history[i].query);
        e += L"}";
    }
    e += L"]";
    e += L",\"text\":"; AppendJsonString(e, d.text);
    e += L"}";
    return e;
}

// =============================================================================
//  Entry points (exported via xways-xml-viewer.def)
// =============================================================================
extern "C" {

LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HWND hMainWnd, void* lpReserved) {
    int missing = RetrieveFunctionPointers();
    if (nFlags & 0x20) return (missing > 0) ? -1 : 1;   // XT_INIT_QUICKCHECK
    g_hMainWnd = hMainWnd;
    const DWORD ver = (nVersion >> 16) & 0xFFFF;
    const DWORD sr  = (nVersion >>  8) & 0xFF;
    Logf(L"%s — X-Ways v%lu.%lu SR-%lu (%d missing exports) — loaded; XT_Init flags=0x%02lX",
         VERSION, (unsigned long)(ver / 100), (unsigned long)((ver % 100) / 10), (unsigned long)sr, missing, (unsigned long)nFlags);
    if (nFlags & 0x40) return (missing > 0) ? -1 : 1;   // XT_INIT_ABOUTONLY: no UI setup

    LoadCfg();
    if (!g_history.empty()) LogVerbosef(L"loaded %llu history entries", (unsigned long long)g_history.size());

    // Decide the mode for the whole session.
    bool runtime = false;
    if (g_cfgBasic) {
        Log(L"mode=basic (cfg): static colour-coded HTML, no WebView2");
    } else {
        LPWSTR rv = nullptr;
        if (SUCCEEDED(GetAvailableCoreWebView2BrowserVersionString(nullptr, &rv)) && rv) {
            runtime = true;
            LogVerbosef(L"WebView2 Runtime available: %s", rv);
            CoTaskMemFree(rv);
        } else {
            Log(L"WebView2 Runtime NOT found — falling back to basic mode (static HTML) for this session. Install the Evergreen WebView2 Runtime from Microsoft for the live XPath view.");
        }
    }
    g_hosted = !g_cfgBasic && runtime;
    if (!g_hosted) return (missing > 0) ? -1 : 1;

    HRESULT ci = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    g_comInitedHere = (ci == S_OK);
    if (ci == RPC_E_CHANGED_MODE) Logf(L"COM already initialised MTA on this thread — WebView2 needs STA; hosting may fail");

    g_pageHtml = LoadResourceText(IDR_VIEWER_HTML);
    if (g_pageHtml.empty()) Log(L"embedded page resource missing — the live view will be blank");
    g_hMsgWnd = CreateWindowExW(0, L"STATIC", L"xways-xml-viewer-msg", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, g_hSelf, nullptr);
    Log(L"mode=live: XPath tree view hosted in the preview pane (WebView2)");
    return (missing > 0) ? -1 : 1;
}

LONG __stdcall XT_About(HWND hParentWnd, void* lpReserved) {
    std::wstring msg = NAME; msg += L" "; msg += VERSION; msg += L"\n"; msg += DESCRIPTION;
    msg += L"\nRegister under Options | Viewer Programs | Load viewer X-Tensions. Live view needs the Edge WebView2 Runtime; set mode=basic in the cfg for the static view.";
    if (XWF_OutputMessage) XWF_OutputMessage(msg.c_str(), 0);
    return 0;
}

// *nResSize: -1 = not our file type, -2 = error, 0 = no data, >0 = byte length.
PVOID __stdcall XT_View(HANDLE hItem, LONG nItemID, HANDLE hVolume, HANDLE hEvidence, PVOID lpReserved, PINT64 nResSize) {
    const long callNo = ++g_viewCalls;
    std::wstring typeDescr;
    const wchar_t* how = L"";
    const wchar_t* nmRaw = XWF_GetItemName ? XWF_GetItemName(nItemID) : nullptr;
    std::wstring name = nmRaw ? nmRaw : L"<unnamed>";

    if (!IsXmlItem(hItem, nItemID, typeDescr, &how)) {
        ShowWeb(false);
        g_itemLive = false;
        LogVerbosef(L"XT_View #%ld item=%ld \"%s\" type=\"%s\" -> not XML, declining (-1)", callNo, nItemID, name.c_str(), typeDescr.c_str());
        *nResSize = -1;
        return nullptr;
    }

    INT64 size = 0;
    if (XWF_GetSize) size = XWF_GetSize(hItem, nullptr);
    if (size <= 0 && XWF_GetItemSize) size = XWF_GetItemSize(nItemID);
    if (size <= 0) { ShowWeb(false); *nResSize = 0; return nullptr; }

    const INT64 cap = g_capBytes;
    const bool truncated = size > cap;
    const DWORD toRead = (DWORD)(truncated ? cap : size);
    std::vector<BYTE> raw(toRead);
    DWORD got = XWF_Read ? XWF_Read(hItem, 0, raw.data(), toRead) : 0;
    if (got == 0) {
        Logf(L"XT_View #%ld item=%ld: XWF_Read returned 0 of %lu bytes", callNo, nItemID, (unsigned long)toRead);
        ShowWeb(false); *nResSize = -2; return nullptr;
    }
    raw.resize(got);
    Decoded d = DecodeBytes(raw);

    // ---- BASIC mode: static HTML for the viewer component ---------------------
    if (!g_hosted) {
        std::wstring html = BuildStaticHtml(nItemID, name, typeDescr, size, d, truncated);
        LogVerbosef(L"XT_View #%ld item=%ld \"%s\" type=\"%s\" via=%s size=%lld enc=%s -> basic HTML %llu chars%s",
                    callNo, nItemID, name.c_str(), typeDescr.c_str(), how, (long long)size, d.encoding.c_str(),
                    (unsigned long long)html.size(), truncated ? L" (truncated)" : L"");
        return ReturnUtf16(html, nResSize);
    }

    // ---- LIVE mode: hand the document to the hosted page ----------------------
    g_pendingEnvelope = BuildEnvelope(nItemID, name, typeDescr, size, d, truncated);
    g_itemLive = true;

    HWND pane = XWF_GetWindow ? XWF_GetWindow(0, 6) : nullptr;
    LogVerbosef(L"XT_View #%ld item=%ld \"%s\" type=\"%s\" via=%s size=%lld enc=%s pane=0x%p%s",
                callNo, nItemID, name.c_str(), typeDescr.c_str(), how, (long long)size, d.encoding.c_str(), (void*)pane,
                truncated ? L" (truncated)" : L"");

    if (pane && IsWindow(pane)) {
        LogVerbosef(L"  hosted: pane %s, ctrl=%s", DescribePane(pane).c_str(), g_ctrl ? L"reused" : L"new");
        AttachAndShow(pane);
    } else {
        // X-Ways creates the viewer window ~100 ms later; the retry timer parents the
        // WebView onto it. A text buffer here would leave X-Ways in text view for later calls.
        StartRetry();
    }

    // 1-byte NUL buffer: the stock viewer renders nothing; our WebView owns the pane.
    BYTE* buf = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), 0, 1));
    if (!buf) { *nResSize = -2; return nullptr; }
    buf[0] = 0;
    *nResSize = 1;
    return buf;
}

// Mandatory companion of XT_View. Fires when the preview moves on (next selection).
BOOL __stdcall XT_ReleaseMem(PVOID lpBuffer) {
    ++g_releaseCalls;
    g_itemLive = false;
    if (lpBuffer) HeapFree(GetProcessHeap(), 0, lpBuffer);
    return TRUE;
}

LONG __stdcall XT_Done(void* lpReserved) {
    if (g_hMsgWnd) { KillTimer(g_hMsgWnd, kRetryTimerId); KillTimer(g_hMsgWnd, kBeatTimerId); }
    DropController(L"XT_Done");
    g_env.Reset();
    if (g_hMsgWnd) { DestroyWindow(g_hMsgWnd); g_hMsgWnd = nullptr; }
    Logf(L"XT_Done — XT_View %ld call(s), XT_ReleaseMem %ld call(s) this session (%s mode)",
         g_viewCalls.load(), g_releaseCalls.load(), g_hosted ? L"live" : L"basic");
    if (g_comInitedHere) { CoUninitialize(); g_comInitedHere = false; }
    return 0;
}

} // extern "C"

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { g_hSelf = h; DisableThreadLibraryCalls(h); }
    return TRUE;
}
