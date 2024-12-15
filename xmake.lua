
target("puppy")

    add_defines('PUPPY_RTOS')
    add_files("*.c", {cxflags = "-Wall -Werror"})
    add_includedirs(".")

if is_config("build_board", "qemu-virt-riscv") then
    add_files("arch/arch_riscv.c")
else
    add_files("arch/arch_cortex-m.c")
end
