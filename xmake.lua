
target("puppy")

    add_defines('PUPPY_RTOS')
    add_files("*.c", {cxflags = "-Wall -Werror --coverage"})
    add_includedirs(".")

if is_config("build_board", "qemu-virt-riscv") then
    add_files("arch/**.c")
else
    add_files("arch/**.c")
end
