#include <Windows.h>

#include <iostream>

//#include "hello.exe.h"

VOID FixImageIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
{
  PIMAGE_THUNK_DATA thunk;
  PIMAGE_THUNK_DATA fixup;
  DWORD iat_rva;
  SIZE_T iat_size;
  HMODULE import_base;
  PIMAGE_IMPORT_DESCRIPTOR import_table =
      (PIMAGE_IMPORT_DESCRIPTOR)(nt_header->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                     .VirtualAddress +
                                 (UINT_PTR)dos_header);

  DWORD iat_loc =
      (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]
           .VirtualAddress)
          ? IMAGE_DIRECTORY_ENTRY_IAT
          : IMAGE_DIRECTORY_ENTRY_IMPORT;

  iat_rva = nt_header->OptionalHeader.DataDirectory[iat_loc].VirtualAddress;
  iat_size = nt_header->OptionalHeader.DataDirectory[iat_loc].Size;

  LPVOID iat = (LPVOID)(iat_rva + (UINT_PTR)dos_header);
  DWORD op;
  VirtualProtect(iat, iat_size, PAGE_READWRITE, &op);
  while (import_table->Name)
  {
    import_base =
        LoadLibraryA((LPCSTR)(import_table->Name + (UINT_PTR)dos_header));
    fixup =
        (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
    if (import_table->OriginalFirstThunk)
    {
      thunk = (PIMAGE_THUNK_DATA)(import_table->OriginalFirstThunk +
                                  (UINT_PTR)dos_header);
    }
    else
    {
      thunk =
          (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
    }

    while (thunk->u1.Function)
    {
      PCHAR func_name;
      if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
      {
        fixup->u1.Function = (UINT_PTR)GetProcAddress(
            import_base, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
      }
      else
      {
        func_name =
            (PCHAR)(((PIMAGE_IMPORT_BY_NAME)(thunk->u1.AddressOfData))->Name +
                    (UINT_PTR)dos_header);
        fixup->u1.Function = (UINT_PTR)GetProcAddress(import_base, func_name);
      }
      fixup++;
      thunk++;
    }
    import_table++;
  }
  return;
}

LPVOID MapImageToMemory(LPVOID base_addr)
{
  LPVOID mem_image_base = NULL;
  PIMAGE_DOS_HEADER raw_image_base = (PIMAGE_DOS_HEADER)base_addr;

  if (IMAGE_DOS_SIGNATURE != raw_image_base->e_magic)
    return NULL;

  PIMAGE_NT_HEADERS nt_header =
      (PIMAGE_NT_HEADERS)(raw_image_base->e_lfanew + (UINT_PTR)raw_image_base);
  if (IMAGE_NT_SIGNATURE != nt_header->Signature)
    return NULL;

  // only 64bit modules will be loaded
  if (IMAGE_FILE_MACHINE_AMD64 != nt_header->FileHeader.Machine)
    return NULL;

  // Not going to bother with .net
  if (nt_header->OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
          .VirtualAddress)
    return NULL;

  PIMAGE_SECTION_HEADER section_header =
      (PIMAGE_SECTION_HEADER)(raw_image_base->e_lfanew + sizeof(*nt_header) +
                              (UINT_PTR)raw_image_base);

  mem_image_base =
      VirtualAlloc((LPVOID)(nt_header->OptionalHeader.ImageBase),
                   nt_header->OptionalHeader.SizeOfImage,
                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (NULL == mem_image_base)
  {
    mem_image_base =
        VirtualAlloc(NULL, nt_header->OptionalHeader.SizeOfImage,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  }

  if (NULL == mem_image_base)
    return NULL;

  memcpy(mem_image_base, (LPVOID)raw_image_base,
         nt_header->OptionalHeader.SizeOfHeaders);

  for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
  {
    memcpy(
        (LPVOID)(section_header->VirtualAddress + (UINT_PTR)mem_image_base),
        (LPVOID)(section_header->PointerToRawData + (UINT_PTR)raw_image_base),
        section_header->SizeOfRawData);
    section_header++;
  }
  return mem_image_base;
}

BOOL FixImageRelocations(PIMAGE_DOS_HEADER dos_header,
                         PIMAGE_NT_HEADERS nt_header,
                         ULONG_PTR delta)
{
  ULONG_PTR size;
  PULONG_PTR intruction;
  PIMAGE_BASE_RELOCATION reloc_block =
      (PIMAGE_BASE_RELOCATION)(nt_header->OptionalHeader
                                   .DataDirectory
                                       [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                   .VirtualAddress +
                               (UINT_PTR)dos_header);

  while (reloc_block->VirtualAddress)
  {
    size = (reloc_block->SizeOfBlock - sizeof(reloc_block)) / sizeof(WORD);
    PWORD fixup = (PWORD)((ULONG_PTR)reloc_block + sizeof(reloc_block));
    for (int i = 0; i < size; i++, fixup++)
    {
      if (IMAGE_REL_BASED_DIR64 == *fixup >> 12)
      {
        intruction = (PULONG_PTR)(reloc_block->VirtualAddress +
                                  (ULONG_PTR)dos_header + (*fixup & 0xfff));
        *intruction += delta;
      }
    }
    reloc_block = (PIMAGE_BASE_RELOCATION)(reloc_block->SizeOfBlock +
                                           (ULONG_PTR)reloc_block);
  }
  return TRUE;
}

void handle_TLS(PIMAGE_DOS_HEADER image_base, PIMAGE_NT_HEADERS nt_header)
{
  if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
  {
    PIMAGE_TLS_DIRECTORY tls =
        (PIMAGE_TLS_DIRECTORY)((UINT_PTR)image_base +
                               nt_header->OptionalHeader
                                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
                                   .VirtualAddress);
    PIMAGE_TLS_CALLBACK *tlsCallback =
        (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
    while (*tlsCallback)
    {
      printf("[+] Found TLS callback at %p\n", (void *)tlsCallback);
      (*tlsCallback)((LPVOID)image_base, DLL_PROCESS_ATTACH, NULL);
      tlsCallback++;
    }
  }
}

/*int execute(LPVOID rawdata)
{
  PIMAGE_DOS_HEADER image_base =
      (PIMAGE_DOS_HEADER)MapImageToMemory((LPVOID)rawdata);
  if (!image_base)
  {
    return 1;
  }
  PIMAGE_NT_HEADERS nt_header =
      (PIMAGE_NT_HEADERS)(image_base->e_lfanew + (UINT_PTR)image_base);
  FixImageIAT(image_base, nt_header);
  if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .VirtualAddress)
  {
    ptrdiff_t delta = (ptrdiff_t)((PBYTE)image_base -
                                  (PBYTE)nt_header->OptionalHeader.ImageBase);
    if (delta)
      FixImageRelocations(image_base, nt_header, delta);
  }
  handle_TLS(image_base, nt_header);
  LPVOID oep = (LPVOID)(nt_header->OptionalHeader.AddressOfEntryPoint +
                        (UINT_PTR)image_base);
  ((void (*)())(oep))();
  return 0;
}*/

int execute_pe(LPCSTR path)
{
  PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)LoadLibrary(path);//works
  if (!image_base)
  {
    return 1;
  }
  PIMAGE_NT_HEADERS nt_header =
      (PIMAGE_NT_HEADERS)(image_base->e_lfanew + (UINT_PTR)image_base);
  FixImageIAT(image_base, nt_header);
  if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .VirtualAddress)
  {
    ptrdiff_t delta = (ptrdiff_t)((PBYTE)image_base -
                                  (PBYTE)nt_header->OptionalHeader.ImageBase);
    if (delta)
      FixImageRelocations(image_base, nt_header, delta);
  }
  handle_TLS(image_base, nt_header);
  LPVOID oep = (LPVOID)(nt_header->OptionalHeader.AddressOfEntryPoint +
                        (UINT_PTR)image_base);
  ((void (*)())(oep))();
  return 0;
}


int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    printf("Usage: %s <path to PE file>\n", argv[0]);
    return 1;
  }
  //execute((LPVOID)rawdata);
  execute_pe(LPCSTR(argv[1]));
  return 0;
}