ENTRY(_start)

PHDRS
{
  ram  PT_LOAD FILEHDR PHDRS ;
}

ram_min = 0;

SECTIONS
{
  /* Mapping the program headers and note into RAM makes the file smaller. */
  . = ram_min;
  . += SIZEOF_HEADERS;

  /* These sections are mapped into RAM from the file. Omitting :ram from
     later sections avoids emitting empty sections in the final binary.       */
  data_start = .;
  .rodata : { *(.rodata .rodata.*) } :ram
  . = ALIGN(4K);
  text_start = .;
  .text   : { *(.text .text.*)     }
  .text32 : { *(.text32)           }
  . = ALIGN(4K);
  text_end = .;
  .data   : { *(.data .data.*)     }
  data_size = . - data_start;

  /* The BSS section isn't mapped from file data. It is just zeroed in RAM. */
  .bss : {
    bss_start = .;
    *(.bss .bss.*)
    bss_size = . - bss_start;
  }
}

