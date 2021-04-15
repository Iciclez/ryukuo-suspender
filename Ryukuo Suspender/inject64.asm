
.code

COMMENT #

dword external_loadlibraryex_function(inject::loadlibraryex_parameter *parameter)
{
	return parameter->address(parameter->filename, parameter->file, parameter->flags) == 0;
}

size = 36
#

external_loadlibraryex_function proc
	sub rsp, 28h
	mov r8d, [rcx+18h]
	mov rax, rcx
	mov rdx, [rcx+10h]
	mov rcx, [rcx+08h]
	call qword ptr [rax]
	xor ecx, ecx
	test rax, rax
	sete cl
	mov eax, ecx
	add rsp, 28h
	ret
external_loadlibraryex_function endp

COMMENT #

dword external_ldrloaddll_function(inject::ldrloaddll_parameter *parameter)
{
	parameter->rtlinitunicodestring(parameter->module_filename, parameter->filename);
	return parameter->address(parameter->pathtofile, parameter->flags, parameter->module_filename, parameter->module_handle) != STATUS_SUCCESS;
}

size = 52
#

external_ldrloaddll_function proc
	push rbx
	sub rsp, 20h
	mov rdx, [rcx+10h]
	mov rbx, rcx
	mov rcx, [rcx+28h]
	call qword ptr [rbx+08h]
	mov r9, [rbx+30h]
	mov r8, [rbx+28h]
	mov edx, [rbx+20h]
	mov rcx, [rbx+18h]
	call qword ptr [rbx]
	xor ecx, ecx
	test eax, eax
	setne cl
	mov eax, ecx
	add rsp, 20h
	pop rbx
	ret 
external_ldrloaddll_function endp

end