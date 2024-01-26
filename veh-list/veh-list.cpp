#include <iostream>
#include <Windows.h>
#include <WinBase.h>
#include <winternl.h>
#include <format>
#include "structs.hpp"

typedef struct _LDRP_VECTOR_HANDLER_LIST {
  PSRWLOCK   LdrpVehLock;
  LIST_ENTRY LdrpVehList;
  PSRWLOCK   LdrpVchLock;
  LIST_ENTRY LdrpVchList;
} LDRP_VECTOR_HANDLER_LIST, *PLDRP_VECTOR_HANDLER_LIST;

typedef struct _VECTOR_HANDLER_ENTRY {
  LIST_ENTRY ListEntry;
  PLONG64    pRefCount;  // ProcessHeap allocated, initialized with 1
  DWORD      unk_0;      // always 0
  DWORD      pad_0;
  PVOID      EncodedHandler;
} VECTOR_HANDLER_ENTRY, *PVECTOR_HANDLER_ENTRY;

template<typename T>
T Read(DWORD64 address) {
  T buffer{};
  ReadProcessMemory(GetCurrentProcess(), (LPVOID)address, &buffer, sizeof(T), NULL);
  return buffer;
}

auto Rel32ToAbs(void* adr, uint64_t instrSize) -> void* {
  uint8_t* next = reinterpret_cast<decltype(next)>(adr) + instrSize;
  return next + (*reinterpret_cast<uint32_t*>(next - 4));
}

LONG CALLBACK VectoredExceptionHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
  // Continue the search for other exception handlers.
  return EXCEPTION_CONTINUE_SEARCH;
}

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle,
    PROCESSINFOCLASS                                        ProcessInformationClass,
    PVOID                                                   ProcessInformation,
    ULONG                                                   ProcessInformationLength,
    PULONG                                                  ReturnLength);

// clang-format off
ULONG GetProcessCookie() {
  ULONG cookie    = 0;
  DWORD retLength = 0;

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");

  NtQueryInformationProcess_t NtQueryInformationProcess = 
      reinterpret_cast<NtQueryInformationProcess_t>(
          GetProcAddress(ntdll, "NtQueryInformationProcess"));

  NTSTATUS success = NtQueryInformationProcess(
      GetCurrentProcess(), 
      (PROCESSINFOCLASS)PIC::ProcessCookie, 
      &cookie, sizeof(cookie), &retLength);

  if (success < 0)
    return 0;

  return cookie;
}
// clang-format on

#include "ida.hpp"

// Rebuilt decode pointer function from IDA (ntdll)
PVOID RebuiltDecodePointer(PVOID pointer) {
  static ULONG processCookie = 0;

  if (!processCookie) {
    processCookie = GetProcessCookie();

    if (!processCookie)
      return 0;
  }

  return (LPVOID)(__ROL8__((ULONGLONG)pointer, processCookie & 0x3F) ^ processCookie);
}

int main() {
  auto pNtdll = GetModuleHandleA("ntdll.dll");

  // Using this address for later so theres less memory to sig scan
  // RtlAddVectoredExceptionHandler + 0x3 = RtlpAddVectoredHandler:
  //
  // .text:0000000000084510                 xor     r8d, r8d
  // .text:0000000000084513                 jmp     RtlpAddVectoredHandler
  BYTE* RtlpAddVectoredHandler = reinterpret_cast<BYTE*>(GetProcAddress(pNtdll, "RtlAddVectoredExceptionHandler")) + 0x3;

  std::printf("RtlpAddVectoredHandler: 0x%p\n", RtlpAddVectoredHandler);

  // Signature (for later): 48 8D 3D CE 6D 11 00
  // .text:0000000000084633                 lea     rdi, LdrpVectorHandlerList
  auto pVehList = reinterpret_cast<PLDRP_VECTOR_HANDLER_LIST>((uintptr_t)pNtdll + 0x84633);

  // Resolve the real address of the VEH list (as its pointer is rip relative)
  auto resolvedVehList = (PLDRP_VECTOR_HANDLER_LIST)Rel32ToAbs(pVehList, 0x7);

  std::printf("VEH list PTR: 0x%p\n", pVehList);
  std::printf("Real VEH list: 0x%p\n", resolvedVehList);

  AddVectoredExceptionHandler(false, (PVECTORED_EXCEPTION_HANDLER)VectoredExceptionHandler);

  LIST_ENTRY* pListHead = &resolvedVehList->LdrpVehList;

  std::cout << "-----------------------------\n";

  for (LIST_ENTRY* pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink) {
    PVECTOR_HANDLER_ENTRY pEntry            = CONTAINING_RECORD(pListEntry, VECTOR_HANDLER_ENTRY, ListEntry);
    LPVOID                pExceptionHandler = RebuiltDecodePointer(pEntry->EncodedHandler);

    TCHAR modName[MAX_PATH];
    GetModuleNameFromAddress((HANDLE)-1, pExceptionHandler, modName);

    std::printf("VEH Ptr: 0x%p | Module: %ws\n", pExceptionHandler, modName);
  }

  std::cout << "-----------------------------\n";

  std::printf("VEHs parsed!\n");

  system("pause");

  return 0;
}