ENTRY(kloader_boot)

SECTIONS
{
  . = 1M + 512;
  .start : {
      *(.start)
  }

  .note :
  {
    KEEP(*(.note))
  }

  data_start = .;
  
  .rodata : { *(.rodata .rodata.*) } :ram

  /* Keep BSS here so that objcopy has a gap for it. */ 
  .bss : {
    bss_start = .;
    *(.bss .bss.*)
    bss_size = . - bss_start;
  }
 
  . = ALIGN(4K);
  text_start = .;
  .text   : { *(.text .text.*)     }
  .text32 : { *(.text32)           }
  . = ALIGN(4K);
  text_end = .;
  .data   : { *(.data .data.*)     }
  data_size = . - data_start;

  /* Strip symbols from the output binary (comment out to get symbols) */
  /*
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
  */
}
