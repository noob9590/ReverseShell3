#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include "rc4.h"


#pragma warning (disable : 6387)
#pragma warning (disable : 4013)
#pragma warning (disable : 4047)

#ifdef _WIN64

typedef UINT64 ADDRSIZE;
#define _reloc_type IMAGE_REL_BASED_DIR64

#else

typedef UINT32 ADDRSIZE;
#define _reloc_type IMAGE_REL_BASED_HIGHLOW

#endif // _WIN64

void* LoadPE(char* pe_raw)
{
	// dos header
	IMAGE_DOS_HEADER* ptr_dos_header = (IMAGE_DOS_HEADER*)pe_raw;
	// nt headers
	IMAGE_NT_HEADERS* ptr_nt_headers = (IMAGE_NT_HEADERS*)((char*)ptr_dos_header + ptr_dos_header->e_lfanew);
	// importent attributes

	ADDRSIZE preffered_image_base = ptr_nt_headers->OptionalHeader.ImageBase;
	ADDRSIZE entry_point = ptr_nt_headers->OptionalHeader.AddressOfEntryPoint;
	DWORD size_of_image = ptr_nt_headers->OptionalHeader.SizeOfImage;
	DWORD size_of_headers = ptr_nt_headers->OptionalHeader.SizeOfHeaders;

	// allocate space for the pe in the process space memory
	char* image_base = (char*)VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!image_base)
	{
		fprintf(stderr, "Error while trying to allocate memory\n");
		return NULL;
	}

	// copy to headers
	memcpy(image_base, pe_raw, size_of_headers);

	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(ptr_nt_headers + 1);
	size_t num_of_sections = ptr_nt_headers->FileHeader.NumberOfSections;

	// copy the raw data to memory
	for (size_t i = 0; i < num_of_sections; i++)
	{
		char* virtual_addr = image_base + sections[i].VirtualAddress;

		if (sections[i].SizeOfRawData > 0)
		{
			memcpy(virtual_addr, pe_raw + sections[i].PointerToRawData, sections[i].SizeOfRawData);
		}

		else
		{
			memset(virtual_addr, 0, sections[i].Misc.VirtualSize);
		}
	}

	// manage imports
	IMAGE_DATA_DIRECTORY* data_dir = ptr_nt_headers->OptionalHeader.DataDirectory;
	IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(image_base + data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// loop over all the modules
	for (size_t i = 0; import_descriptors[i].Name != NULL; i++)
	{
		char* name = image_base + import_descriptors[i].Name;

		HMODULE module = LoadLibraryA(name);

		if (!module)
		{
			fprintf(stderr, "Error while trying to load library %s\n", name);
			return NULL;
		}

		// import name table
		PIMAGE_THUNK_DATA import_name_table = (PIMAGE_THUNK_DATA)(image_base + import_descriptors[i].OriginalFirstThunk);

		// import address table
		PIMAGE_THUNK_DATA import_address_table = (PIMAGE_THUNK_DATA)(image_base + import_descriptors[i].FirstThunk);

		// loop over import name table
		for (size_t j = 0; import_name_table[j].u1.AddressOfData != 0; j++)
		{

			UINT64 func_addr = import_name_table[j].u1.AddressOfData;
			void* h_function = NULL;

			// import by name
			if (!(func_addr & IMAGE_ORDINAL_FLAG))
			{
				PIMAGE_IMPORT_BY_NAME image_import = (PIMAGE_IMPORT_BY_NAME)(image_base + func_addr);
				char* func_name = image_import->Name;
				h_function = GetProcAddress(module, func_name);
			}

			// import by ordinal
			else
			{
				h_function = GetProcAddress(module, (LPSTR)((WORD)func_addr));
			}

			if (!h_function)
			{
				fprintf(stderr, "Error while trying to import api function by name/ordinal\n");
				return NULL;
			}

			// add the function address to the IAT.
			import_address_table[j].u1.Function = (ADDRSIZE)h_function;
		}
	}

	// manage relocation
	PIMAGE_BASE_RELOCATION ptr_relocation = (PIMAGE_BASE_RELOCATION)(image_base + data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	// the delta between the preffered address and the real address that we loaded the pe
	ADDRSIZE address_delta = ((ADDRSIZE)image_base) - ptr_nt_headers->OptionalHeader.ImageBase;

	// if relocations exist and the pe did not load at the preffered address
	if (ptr_relocation != NULL && address_delta != 0)
	{
		while (ptr_relocation->VirtualAddress != NULL)
		{
			DWORD num_of_entries = (ptr_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			WORD* entries = (WORD*)(ptr_relocation + 1);

			for (size_t i = 0; i < num_of_entries; i++)
			{
				int type = entries[i] >> 12;
				int offset = entries[i] & 0x0fff;
				ADDRSIZE* address_to_change = (ADDRSIZE*)(image_base + ptr_relocation->VirtualAddress + offset);

				if (type == _reloc_type)
				{
					*address_to_change += address_delta;
				}
			}

			ptr_relocation = (PIMAGE_BASE_RELOCATION)(((ADDRSIZE)ptr_relocation) + ptr_relocation->SizeOfBlock);
		}
	}

	DWORD oldProtections;
	VirtualProtect(image_base, size_of_headers, PAGE_READONLY, &oldProtections);

	// match premissions
	for (size_t i = 0; i < num_of_sections; i++)
	{
		char* section_address = image_base + sections[i].VirtualAddress;
		DWORD permissions = sections[i].Characteristics;
		DWORD new_permissions = 0;

		if (permissions & IMAGE_SCN_MEM_EXECUTE)
		{
			if (permissions & IMAGE_SCN_MEM_WRITE)
			{
				new_permissions = PAGE_EXECUTE_READWRITE;
			}

			else
			{
				new_permissions = PAGE_EXECUTE_READ;
			}
		}

		else
		{
			if (permissions & IMAGE_SCN_MEM_WRITE)
			{
				new_permissions = PAGE_READWRITE;
			}

			else
			{
				new_permissions = PAGE_READONLY;
			}
		}

		VirtualProtect(section_address, sections[i].Misc.VirtualSize, new_permissions, &oldProtections);
	}

	return (void*)(image_base + entry_point);
}


char* PatternScan(char* address, size_t scanSize, const char* mask, char* pattern, size_t patternSize)
{
	int foundPattern;

	for (size_t i = 0; i < scanSize - patternSize; i++)
	{

		foundPattern = 1;

		for (size_t j = 0; j < patternSize; j++)
		{
			if (mask[j] == '?')
			{
				continue;
			}

			if (pattern[j] != address[i + j])
			{
				foundPattern = 0;
				break;
			}
		}

		if (foundPattern)
		{
			return address + i;
		}
	}

	return NULL;
}


PIMAGE_RESOURCE_DATA_ENTRY FindStringResource(PIMAGE_RESOURCE_DIRECTORY resourcesDir, int type, const wchar_t* name, int lang)
{
	PIMAGE_RESOURCE_DIRECTORY resourceLevel = resourcesDir;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resourceLevel + 1);
	int NumOfEntries = resourceLevel->NumberOfNamedEntries + resourceLevel->NumberOfIdEntries;
	int foundResource = 0;

	for (size_t i = 0; i < NumOfEntries; i++)
	{
		if (entries[i].Id == type)
		{
			foundResource = 1;
			resourceLevel = (PIMAGE_RESOURCE_DIRECTORY)((char*)resourcesDir + entries[i].OffsetToDirectory);
			entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resourceLevel + 1);
			NumOfEntries = resourceLevel->NumberOfNamedEntries + resourceLevel->NumberOfIdEntries;
			break;
		}
	}

	if (!foundResource)
	{
		return NULL;
	}

	foundResource = 0;

	for (size_t i = 0; i < NumOfEntries; i++)
	{
		if (entries[i].NameIsString)
		{
			wchar_t* resourceName = (wchar_t*)((char*)resourcesDir + entries[i].NameOffset);
			int nameSize = (int)resourceName[0];

			if (wcsncmp(resourceName + 1, name, nameSize) == 0)
			{
				foundResource = 1;
				resourceLevel = (PIMAGE_RESOURCE_DIRECTORY)((char*)resourcesDir + entries[i].OffsetToDirectory);
				entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resourceLevel + 1);
				NumOfEntries = resourceLevel->NumberOfNamedEntries + resourceLevel->NumberOfIdEntries;
				break;
			}
		}
	}

	if (!foundResource)
	{
		return NULL;
	}

	for (size_t i = 0; i < NumOfEntries; i++)
	{
		if (entries[i].Id == lang)
		{
			return (PIMAGE_RESOURCE_DATA_ENTRY)((char*)resourcesDir + entries[i].OffsetToData);
		}
	}

	return NULL;
}

APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	char* unpacked_VA = (char*)GetModuleHandleA(NULL);

	PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)unpacked_VA;
	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)(((char*)DOSHeader) + DOSHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(NTHeader + 1);
	PIMAGE_DATA_DIRECTORY dataDir = (PIMAGE_DATA_DIRECTORY)NTHeader->OptionalHeader.DataDirectory;
	PIMAGE_RESOURCE_DIRECTORY resourcesDir = (PIMAGE_RESOURCE_DIRECTORY)((char*)unpacked_VA + dataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	PIMAGE_RESOURCE_DATA_ENTRY resourceData = FindStringResource(resourcesDir, 10, L"data", 0);

	if (!resourceData)
	{
		fprintf(stderr, "Could not find resource.\n");
		exit(EXIT_FAILURE);
	}

	char* pattern = unpacked_VA + resourceData->OffsetToData;
	char* key = pattern + 16;
	char* addressOfPE = PatternScan(unpacked_VA, NTHeader->OptionalHeader.SizeOfImage, pattern, pattern, 16);

	if (!addressOfPE)
	{
		fprintf(stderr, "Could not find PE in memory,\n");
		exit(EXIT_FAILURE);
	}

	UINT64 sectionAddress = ((UINT64)addressOfPE - (UINT64)unpacked_VA) - ((UINT64)addressOfPE - (UINT64)unpacked_VA) % 0x1000;
	SIZE_T sectionSize = -1;
	int PESize = -1;

	for (size_t i = 0; i < NTHeader->FileHeader.NumberOfSections; i++)
	{
		if (sectionAddress == sections[i].VirtualAddress)
		{
			sectionSize = sections[i].Misc.VirtualSize;
			PESize = (int)(sectionSize - ((UINT64)addressOfPE - (UINT64)unpacked_VA) % 0x1000);
			break;
		}
	}

	if (sectionSize == -1)
	{
		fprintf(stderr, "Cloud find section size\n");
		exit(EXIT_FAILURE);
	}

	DWORD oldProtect;
	VirtualProtect((LPVOID)(unpacked_VA + sectionAddress), sectionSize, PAGE_READWRITE, &oldProtect);

	struct rc4_state s;
	rc4_setup(&s, (unsigned char*)key, 16);
	rc4_crypt(&s, (unsigned char*)addressOfPE, PESize);

	void* entry_point = LoadPE(addressOfPE);
	if (entry_point != NULL)
	{
		((void(*)(void))entry_point)();
	}

	VirtualProtect((LPVOID)(unpacked_VA + sectionAddress), sectionSize, oldProtect, NULL);

	return 0;
}