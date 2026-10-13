// Imported function names -> capability, with MITRE ATT&CK technique.
// Matching ignores case and the A/W/Ex/ExA/ExW suffixes of Windows APIs.
export const CAPABILITIES = [
  { id: 'injection', attack: 'T1055', label: 'process injection', apis: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtWriteVirtualMemory', 'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC', 'NtQueueApcThread', 'SetThreadContext', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'NtMapViewOfSection', 'VirtualProtectEx'] },
  { id: 'anti-debug', attack: 'T1622', label: 'debugger evasion', apis: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString', 'NtSetInformationThread', 'ptrace'] },
  { id: 'keylogging', attack: 'T1056.001', label: 'keylogging', apis: ['SetWindowsHook', 'GetAsyncKeyState', 'GetKeyboardState', 'RegisterRawInputDevices'] },
  { id: 'screen-capture', attack: 'T1113', label: 'screen capture', apis: ['BitBlt', 'GetDesktopWindow', 'CreateCompatibleBitmap'] },
  { id: 'credential-access', attack: 'T1003', label: 'credential access', apis: ['CredEnumerate', 'CredRead', 'LsaRetrievePrivateData', 'CryptUnprotectData', 'MiniDumpWriteDump', 'SamIConnect', 'LsaEnumerateLogonSessions'] },
  { id: 'download', attack: 'T1105', label: 'downloads files', apis: ['URLDownloadToFile', 'URLDownloadToCacheFile', 'InternetReadFile', 'InternetOpenUrl', 'WinHttpReadData', 'HttpSendRequest'] },
  { id: 'network', attack: 'T1071', label: 'network communication', apis: ['WSAStartup', 'InternetOpen', 'WinHttpOpen', 'connect', 'send', 'recv', 'socket', 'gethostbyname', 'getaddrinfo', 'DnsQuery'] },
  { id: 'execution', attack: 'T1106', label: 'launches processes', apis: ['CreateProcess', 'ShellExecute', 'WinExec', 'CreateProcessAsUser', 'CreateProcessWithToken', 'execve', 'execvp', 'execl', 'system', 'popen'] },
  { id: 'persistence-registry', attack: 'T1547.001', label: 'registry persistence', apis: ['RegSetValue', 'RegCreateKey', 'SHSetValue'] },
  { id: 'persistence-service', attack: 'T1543.003', label: 'service creation', apis: ['CreateService', 'ChangeServiceConfig', 'StartService'] },
  { id: 'crypto', attack: 'T1486', label: 'encryption APIs', apis: ['CryptEncrypt', 'BCryptEncrypt', 'CryptGenKey', 'CryptImportKey', 'EVP_EncryptInit', 'EVP_EncryptUpdate'] },
  { id: 'privilege', attack: 'T1134', label: 'token manipulation', apis: ['AdjustTokenPrivileges', 'DuplicateToken', 'ImpersonateLoggedOnUser', 'LookupPrivilegeValue', 'setuid'] },
  { id: 'dynamic-loading', attack: 'T1129', label: 'dynamic API resolution', apis: ['LoadLibrary', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress', 'dlopen', 'dlsym'] },
  { id: 'memory-exec', attack: 'T1620', label: 'executable memory allocation', apis: ['VirtualAlloc', 'VirtualProtect', 'NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'mprotect'] },
  { id: 'discovery', attack: 'T1082', label: 'system discovery', apis: ['GetComputerName', 'GetUserName', 'CreateToolhelp32Snapshot', 'Process32First', 'EnumProcesses', 'NetShareEnum'] },
  { id: 'clipboard', attack: 'T1115', label: 'clipboard access', apis: ['GetClipboardData'] },
  { id: 'log-tampering', attack: 'T1070.001', label: 'event log clearing', apis: ['ClearEventLog', 'EvtClearLog'] },
];
const base = (n) => n.replace(/(?<=[a-z0-9])(?:ExA|ExW|Ex|A|W)$/, '').toLowerCase();
/** @param {string[]} names @returns {{id:string,label:string,attack:string,apis:string[]}[]} */
export function capabilities(names) {
  const out = [];
  for (const c of CAPABILITIES) {
    const want = new Set(c.apis.map(base));
    const hit = [...new Set(names.filter((n) => want.has(base(n))))];
    if (hit.length) out.push({ id: c.id, label: c.label, attack: c.attack, apis: hit });
  }
  return out;
}
