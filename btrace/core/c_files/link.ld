SECTIONS
{
    .text : { 
        *(.core*) 
        *(.text*) 
    }

    .handlers : {
        __start_handlers = .;
        KEEP(*(.handlers*))
        __stop_handlers = .;
    }

    .rodata : { *(.rodata*) }
    .data   : { *(.data*) }
    .bss    : { *(.bss*) }
}