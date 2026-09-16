; Author: wizardy0ga
; sep 12 2026
; 
; This program was written to demonstrate a position independent re-write 
; of GetProcAddress from the windows API. Instead of a string, it uses a 
; djb2 hash for function identification. The program is intended to be 
; carved as shellcode from the .text section of the resulting binary 
; and executed using a thread based injection method. 
; 
; The main body of the code will use the re-written GetProcAddress function
; to find LoadLibraryA in kernel32 and load user32.dll into the process. Then
; it locates MessageBoxA from user32.dll and displays a success message.
; Finally, it locates RtlExitUserThread in ntdll.dll and cleanly terminates
; the its thread so the target process stays alive.
; 
; Assemble: nasm -f win64 GetProcAddress.x64.asm
; Link: link.exe /subsystem:console /entry:main GetProcAddress.x64.obj
;
; Tested on:
;   - Windows 10 Pro 22H2 19045.6466
;   - Windows 11 Pro 25H2 26200.9445
;
bits 64
default rel
global main

section .text

main:
    ; Step 1. Get base address of ntdll in the process environment block.
    ;
    xor rax, rax
    mov rax, [gs:0x60]       ; rax = PEB
    mov rax, [rax + 0x18]    ; rax = PEB->LDR
    mov rax, [rax + 0x10]    ; rax = PEB->Ldr->InLoadOrderModuleList->Flink [this.exe]
    mov rax, [rax]           ; rax = LDR_DATA_TABLE_ENTRY, PEB->Ldr->InLoadOrderModuleList->Flink [ntdll.dll]
    mov r15, [rax + 0x30]    ; r15 = (LDR_DATA_TABLE_ENTRY)NtDll.DllBase
    
    ; Step 2. Get the base address of kernel32
    ;
    mov rax, [rax]           ; rax = LDR_DATA_TABLE_ENTRY, PEB->Ldr->InLoadOrderModuleList->Flink [kernel32.dll]
    mov rcx, [rax + 0x30]    ; rcx = (LDR_DATA_TABLE_ENTRY)Kernel32.DllBase
    
    ; Step 3. Call custom getprocaddress to search for LoadLibrary
    ;
    mov rdx, 0x5FBFF0FB      ; rdx = 0x5FBFF0FB ("LoadLibraryA")
    sub rsp, 0x28
    call getprocaddress      ; GetProcAddress(rcx=kernel32.dll, rdx=LoadLibraryA)
    add rsp, 0x28
    cmp rax, 0
    je terminate
    
    ; Step 4. Call LoadLibrary to get User32.dll
    ;
    lea rcx, [user32]       ; rcx = "user32.dll" (lpLibFileName)
    sub rsp, 0x28
    call rax                ; LoadLibraryA(rcx="user32.dll")
    add rsp, 0x28
    cmp rax, 0
    je terminate
    
    ; Step 5. Search for MessageBoxA in user32.dll
    ;
    mov rcx, rax            ; rcx = hModule (user32.dll base address)
    mov rdx, 0x384F14B4     ; rdx = 0x384F14B4 ("MessageBoxA")
    sub rsp, 0x28
    call getprocaddress     ; GetProcAddress(rcx=user32.dll, rdx=MessageBoxA)
    add rsp, 0x28
    cmp rax, 0
    je terminate

    ; Step 6. Call MessageBoxA
    ;
    mov rcx, 0              ; rcx = 0 (hWnd = 0)
    lea rdx, [lpText]       ; rdx = lpText
    lea r8,  [lpCaption]    ; r8 = lpCaption
    mov r9, 0               ; r9 = 0 (uType = MB_OK)
    sub rsp, 0x28
    call rax                ; MessageBoxA(rcx=0, rdx=lpText, r8=lpCaption, r9=MB_OK)
    add rsp, 0x28
    
    ; Step 7. Locate RtlExitUserThread in ntdll. We can't use ExitThread
    ;         since its forwarded. To get around this, we call the function
    ;         its forwarded to which is RtlExitUserThread in ntdll.dll.
    ;
    mov rcx, r15            ; rcx = (LDR_DATA_TABLE_ENTRY)NtDll.DllBase
    mov rdx, 0x8E492B88     ; rdx = 0x8E492B88 "RtlExitUserThread" 
    sub rsp, 0x28
    call getprocaddress     ; GetProcAddress(rcx=ntdll.dll, rdx=RtlExitUserThread)
    cmp rax, 0
    je terminate
    xor rcx, rcx            ; rcx = 0
    sub rsp, 0x28
    call rax                ; RtlExitUserThread(rcx=0)
terminate:
    ret

; __stdcall* GetProcAddress(HMODULE hModule, DWORD Hash)
;                           rcx   = hModule, rdx=Hash
;
; NOTE: This implementation does not support forwarded functions.
;
getprocaddress:
    ; Step 1: get the export directory from hModule
    ;
    mov r11d, [rcx + 0x3C]  ; r11d = e_lfanew
    add r11, rcx            ; r11 = IMAGE_NT_HEADERS
    add r11, 0x88           ; r11 = IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    mov r11d, [r11]         ; r11d = IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add r11, rcx            ; r11 = IMAGE_EXPORT_DIRECTORY

    ; Step 2: search export directory for function
    ;
    mov r10d, [r11 + 0x20]  ; r10d = IMAGE_EXPORT_DIRECTORY.AddressOfNames RVA
    add r10, rcx            ; r10 = Function Name Address array
.get_next_function_name:
    mov eax, 0x1505         ; eax = 0x1505 (hash seed)
    mov r9d, [r10 + rdi * 4]; r9d = Function Name RVA
    add r9, rcx             ; r9 = Function Name
    xor rsi, rsi            ; rsi = 0
.djb2_hash:
    mov sil, [r9]           ; sil = &TargetFunc[i]
    cmp sil, 0              ; check for null terminator. hash complete if true
    je .hash_complete
    mov r8d, eax            ; preserve hash from previous result
    shl eax, 5              ; eax = (hash << 5)
    add eax, r8d            ; eax = ((hash << 5) + hash)
    add eax, esi            ; eax = ((hash << 5) + hash) + char
    inc r9                  ; increment pointer to next byte in string
    jmp .djb2_hash
.hash_complete:
    cmp rax, rdx            ; Check if function hash matches hash parameter
    je .found_function
    cmp edi, [r11 + 0x14]   ; Check if current function index is == IMAGE_EXPORT_DIRECTORY.NumberOfFunctions
    je .end_of_exports
    inc rdi                 ; Continue to next function
    jmp .get_next_function_name
.end_of_exports:
    xor rax, rax
    ret

    ; Step 3: Get the function address
    ; 
.found_function:
    mov eax, [r11 + 0x24]    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals RVA
    add rax, rcx             ; rax = Ordinals Array base
    mov si, [rax + rdi * 2]  ; si = Function Ordinal
    mov eax, [r11 + 0x1C]    ; eax = IMAGE_EXPORT_DIRECTORY.AddresssOfFunctions RVA
    add rax, rcx             ; rax = Function Address Array base
    mov eax, [rax + rsi * 4] ; eax = Function Address RVA
    add rax, rcx             ; rax = Function Address
    xor rsi, rsi             ; rsi = 0 - Clean rsi & rdi indexes for next call usage. 
                             ;           Caller must clean otherwise calling getprocaddress again breaks due to invalid indices. 
    xor rdi, rdi             ; rdi = 0
    ret    

user32:
    db "user32.dll", 0
lpCaption:
    db "x64 Assembly GetProcAddress Rewrite Demo", 0
lpText:
    db "Successfully resolved and executed MessageBoxA!",0