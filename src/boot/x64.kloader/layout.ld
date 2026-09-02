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
  /* Placed here so that .data is the last section before the kernel image:
     a read-only section right before it would share its PT_LOAD, and the
     33 MB gap would be written into the file. */
  .eh_frame_hdr : { *(.eh_frame_hdr) }
  .eh_frame     : { KEEP(*(.eh_frame)) }
  .got          : { *(.got .got.*) }
  .data   : { *(.data .data.*)     }
  data_size = . - data_start;

  /* The kernel ELF, as its own PT_LOAD at the kernel's physical load
     address, so a PVH loader (cloud-hypervisor, Firecracker, QEMU -kernel)
     places it. kloader.bin drops this section: the BIOS path loads the
     kernel from the initrd. Keep in sync with KERNEL_PHYS_START in mm.rs. */
  . = 34M;
  .kernel_image : { KEEP(*(.kernel_image)) }

  /* Strip symbols from the output binary (comment out to get symbols) */
  /*
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
  */
}
