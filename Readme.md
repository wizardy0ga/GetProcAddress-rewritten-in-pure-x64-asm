# About
In my previous write ups about this x64 assembly binge i've been on, i was performing a pebwalk which is essentially doing the job of GetProcAddress one time. Using the knowledge i've gained from those write ups, i've created a GetProcAddress function which allows us to re-use the functionality within the same shellcode blob wile remaining position independent. This will enable us to locate and call multiple functions within the same shellcode blob. Up until now, we have only been calling one function, **WinExec**. This provides a re-usable function for multiple making multiple calls, extending our capabilities.

## Previous write ups
1. [Coding-my-first-position-independent-shellcode-for-windows-from-scratch-in-x64-assembly](https://github.com/wizardy0ga/coding-my-first-position-independent-shellcode-for-windows-from-scratch-in-x64-assembly)
2. [Improving-my-x64-PIC-shellcode-windows-peb-walk](https://github.com/wizardy0ga/improving-my-x64-PIC-shellcode-windows-peb-walk)
3. [djb2-hash-x64-assembly](https://github.com/wizardy0ga/djb2-hash-x64-assembly)
4. [Improving-my-x64-PIC-shellcode-windows-peb-walk-part-2](https://github.com/wizardy0ga/improving-my-x64-PIC-shellcode-windows-peb-walk-part-2)

# Demonstration
To demonstrate the functions ability to repeatedly locate functions which can be dynamically called by our shellcode, i've used it to create a shellcode which uses the function to load user32.dll into the target process via LoadLibrary, then it parses user32.dll for MessageBoxA and pops a message box. Finally, it terminates its own thread to cleanly kill the shellcode without terminating the host process early. This demonstrates its ability to load a new module into the process and then parse the new module for another function to call, using the same function while remaining position independent.

# The code
Instead of using strings, this function uses a hash of the function name which is compared to a live hash of the function name taken when its parsed from the target modules export address table.

```asm
; __stdcall* GetProcAddress(HMODULE hModule, DWORD Hash)
;                           rcx   = hModule, rdx=Hash
;
; NOTE: This implementation does not support forwarded functions.
; Author: wizardy0ga
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
```