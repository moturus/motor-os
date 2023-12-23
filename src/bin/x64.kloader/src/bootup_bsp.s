.section .start, "ax"
.global kloader_boot
.code32

kloader_boot:
    # Stash the PVH start_info struct in %rdi (=%edi).
    movl %ebx, %edi
    movl %eax, %ebx  # in case this is a multiboot2 situation

setup_page_tables:

    # map the first 1G page
    movl $L3_TABLE, %ecx
    movl $0b10000101, %eax  # huge (bit 7), writable (bit 1), present (bit 0)
    movl %eax, (%ecx)

    # First L4 entry points to L3 table
    movl $L3_TABLE, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (L4_TABLE)

enable_paging:
    # Load page table root into CR3
    movl $L4_TABLE, %eax
    movl %eax, %cr3

    # Set CR4.PAE (Physical Address Extension)
    movl %cr4, %eax
    orb  $0b00100000, %al # Set bit 5
    movl %eax, %cr4
    # Set EFER.LME (Long Mode Enable)
    movl $0xC0000080, %ecx
    rdmsr
    orb  $0b00000001, %ah # Set bit 8
    wrmsr
    # Set CRO.PG (Paging)
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

# print '$$' to the serial console, for debugging purposes
# movl $36, %eax
# movl $0x3f8, %edx
# outb %al, %dx
# outb %al, %dx

jump_to_64bit:
    # We are now in 32-bit compatibility mode. To enter 64-bit mode, we need to
    # load a 64-bit code segment into our GDT.
    lgdtl GDT64_PTR
    # Initialize the stack pointer (Rust code always uses the stack)
    # Kernel bootup stack: 32MB
    # movl $0x2000000, %esp
    movl (BOOTUP_STACK_START), %esp  # defined in mm.rs in kloader.
    # Set segment registers to a 64-bit segment.
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %ss

    xor %bp, %bp

    mov $0, %ax
    movw %ax, %gs

    movl %ebx, %edx
    # Set CS to a 64-bit segment and jump to 64-bit Rust code.
    # PVH start_info is in %rdi, the first paramter of the System V ABI.
    ljmpl $0x08, $bsp_start