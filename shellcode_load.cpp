// shellcode_loader_x64.cpp 只能处理64位shellcode
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

using ShellEntry = void(*)(); // 若需返回值，改成 INT(*)()

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("用法: shellcode_loader_x64.exe <shellcode路径>\n");
        return 0;
    }

    const char* path = argv[1];
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] 无法打开文件, err=%lu\n", GetLastError());
        return -1;
    }

    DWORD fsize = GetFileSize(hFile, nullptr);
    if (fsize == INVALID_FILE_SIZE || fsize == 0) {
        printf("[-] GetFileSize 失败, err=%lu\n", GetLastError());
        CloseHandle(hFile);
        return -2;
    }

    void* buf = VirtualAlloc(nullptr, fsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buf) {
        printf("[-] VirtualAlloc 失败, err=%lu\n", GetLastError());
        CloseHandle(hFile);
        return -3;
    }

    DWORD nread = 0;
    if (!ReadFile(hFile, buf, fsize, &nread, nullptr) || nread != fsize) {
        printf("[-] ReadFile 失败, err=%lu\n", GetLastError());
        CloseHandle(hFile);
        VirtualFree(buf, 0, MEM_RELEASE);
        return -4;
    }
    CloseHandle(hFile);

    printf("[+] shellcode 大小: %lu 字节，开始执行...\n", fsize);
    auto fn = reinterpret_cast<ShellEntry>(buf);
    fn();  // 如果 shellcode 不返回，后面不会执行

    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
