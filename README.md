# elf-runtime-encryptor
Encrypts and decrypts functions during runtime. Functions are only decrypted while in use.

Takes advantage of the instrumentation provided by `-finstrument-functions`, and uses the enter/exits to decrypt and then reencrypt memory.

Memory is marked RWX while being instrumented, but is promptly set back to normal RX permissions when normal program flow resumes.

# Live preview
![Code_2025-11-09_19-48-05](https://github.com/user-attachments/assets/aa1e6cb6-55b5-4c12-8051-2078be94fded)


# How it works
The methodology of the elf runtime encryptor is that it locates the "highest" (lowest memory address) call/jmp to `__cyg_profile_func_enter`
It then locates the "lowest" (highest memory address) call/jmp to `__cyg_profile_func_exit`

These values give us the size, and everything between the enter and exit gets encrypted.

This is a left/right comparison of what it looks like in practice with a simple function:
<img width="1708" height="810" alt="image" src="https://github.com/user-attachments/assets/11246ba0-55fe-4f0c-9dba-d4dad61e6a7e" />

You can see that the number of bytes is the same, the encryption key in this example is a single-byte xor of 0x90

# Usage
1. Add `-finstrument-functions` to compile steps.
2. Add `enc.c` into your project. 

If you want, you can dive into `-finstrument-functions-exclude-file-list` and `-finstrument-functions-exclude-function-list` to be more specific.
The flag `__attribute__((no_instrument_function))` can be used to exclude functions from instrumentation / encryption.
