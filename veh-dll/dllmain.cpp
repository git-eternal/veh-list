#include "pch.h"

LONG CALLBACK VectoredExceptionHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
  // Continue the search for other exception handlers.
  return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    MessageBoxA(nullptr, "Injected", "Now adding VEH", MB_OK);
    AddVectoredExceptionHandler(false, (PVECTORED_EXCEPTION_HANDLER)VectoredExceptionHandler);
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH: break;
  }

  return TRUE;
}