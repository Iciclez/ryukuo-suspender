.386
.model flat, c

.code

COMMENT #

dword external_loadlibraryex_function(inject::loadlibraryex_parameter *parameter)
{
	return parameter->address(parameter->filename, parameter->file, parameter->flags) == 0;
}

size = 26
#

external_loadlibraryex_function proc
	push ebp
	mov ebp, esp
	mov eax, [ebp+08h]
	push [eax+0Ch]
	push [eax+08h]
	push [eax+04h]
	mov eax, [eax]
	call eax
	neg eax
	sbb eax, eax
	inc eax
	pop ebp
	ret
external_loadlibraryex_function endp

COMMENT #

dword external_ldrloaddll_function(inject::ldrloaddll_parameter *parameter)
{
	parameter->rtlinitunicodestring(parameter->module_filename, parameter->filename);
	return parameter->address(parameter->pathtofile, parameter->flags, parameter->module_filename, parameter->module_handle) != STATUS_SUCCESS;
}

size = 43
#

external_ldrloaddll_function proc
	push ebp
	mov ebp,esp
	push esi
	mov esi,[ebp+08h]
	push [esi+08h]
	mov eax, [esi+04h]
	push [esi+14h]
	call eax
	push [esi+18h]
	mov eax, [esi]
	push [esi+14h]
	push [esi+10h]
	push [esi+0Ch]
	call eax
	neg eax
	pop esi
	sbb eax, eax
	neg eax
	pop ebp
	ret
external_ldrloaddll_function endp

end