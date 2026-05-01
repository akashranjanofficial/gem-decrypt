#!/usr/bin/env python3
"""
Extract AES key from CPKernel.dll + corem.dll using Unicorn CPU emulator.
Emulates the x86 key derivation code to get the exact key bytes.
"""

from unicorn import *
from unicorn.x86_const import *
import struct

# Memory layout
DLL_BASE   = 0x10000000  # CPKernel.dll base
COREM_BASE = 0x20000000  # corem.dll base  
STACK_BASE = 0x00100000  # Stack
STACK_SIZE = 0x00100000
HEAP_BASE  = 0x00400000  # Heap for allocations
DATA_BASE  = 0x00800000  # Data area for strings

# Load DLL binaries
with open('player_files/app/CPKernel.dll', 'rb') as f:
    cpkernel_data = f.read()
with open('player_files/app/corem.dll', 'rb') as f:
    corem_data = f.read()

# Parse PE sections
def parse_pe_sections(data, base):
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sect_off = pe_off + 24 + opt_size
    sections = []
    for i in range(num_sections):
        off = sect_off + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, off+8)[0]
        vaddr = struct.unpack_from('<I', data, off+12)[0]
        rsize = struct.unpack_from('<I', data, off+16)[0]
        rptr = struct.unpack_from('<I', data, off+20)[0]
        sections.append((name, vaddr, vsize, rptr, rsize))
    return sections

# Map PE into emulator memory
def map_pe(mu, data, base):
    # Map enough space for the PE
    total = max(s[1] + s[2] for s in parse_pe_sections(data, base)) + 0x1000
    total = (total + 0xFFF) & ~0xFFF
    mu.mem_map(base, total)
    # Map headers
    mu.mem_write(base, data[:0x1000])
    # Map sections
    for name, vaddr, vsize, rptr, rsize in parse_pe_sections(data, base):
        section_data = data[rptr:rptr+rsize]
        mu.mem_write(base + vaddr, section_data)

# Heap allocator
heap_ptr = HEAP_BASE

def heap_alloc(size):
    global heap_ptr
    ptr = heap_ptr
    heap_ptr += (size + 0xF) & ~0xF
    return ptr

# Hook for intercepted function calls
hook_returns = {}

def hook_code(mu, address, size, user_data):
    # Intercept calls to corem.dll ordinals and helper functions
    
    # corem.dll Ordinal_3 (CreateContext) at 0x10001280
    if address == COREM_BASE + 0x1280:
        # Allocate a 320-byte context, zero it
        ctx = heap_alloc(0x140)
        for i in range(0x140):
            mu.mem_write(ctx + i, b'\x00')
        # Set mode flag
        mu.mem_write(ctx, struct.pack('<I', 1))  # encrypt mode
        # Set alignment value at ctx+0x124
        align = ((ctx + 0x128 - 8) & ~0xF) - ctx
        # Actually compute as in the original: (0xFFFFFFF8 - ctx) >> 2 & 3
        val = ((0xFFFFFFF8 - ctx) >> 2) & 3
        mu.mem_write(ctx + 0x124, struct.pack('<I', val))
        # Set function pointer at ctx+0x13c (encrypt function)
        mu.mem_write(ctx + 0x13c, struct.pack('<I', COREM_BASE + 0x1940))
        # Set AES tables initialized flag
        mu.mem_write(COREM_BASE + 0xBA38, struct.pack('<I', 1))
        mu.reg_write(UC_X86_REG_EAX, ctx)
        # Skip to ret
        ret_addr = struct.unpack('<I', mu.mem_read(mu.reg_read(UC_X86_REG_ESP), 4))[0]
        mu.reg_write(UC_X86_REG_ESP, mu.reg_read(UC_X86_REG_ESP) + 4)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # corem.dll Ordinal_4 (SetKey32) - we need to capture the key!
    if address == COREM_BASE + 0x1290:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        ctx_ptr = struct.unpack('<I', mu.mem_read(esp+4, 4))[0]
        key_ptr = struct.unpack('<I', mu.mem_read(esp+8, 4))[0]
        key_len = struct.unpack('<I', mu.mem_read(esp+12, 4))[0]
        
        key_bytes = bytes(mu.mem_read(key_ptr, key_len))
        print(f"[!] corem Ordinal_4 SetKey called!")
        print(f"    ctx=0x{ctx_ptr:08x}, key_ptr=0x{key_ptr:08x}, key_len={key_len}")
        print(f"    KEY = {key_bytes.hex()}")
        print(f"    KEY (ASCII) = {repr(key_bytes)}")
        
        # Store key globally
        hook_returns['aes_key_32'] = key_bytes
        
        # Check key_len validity
        if key_len < 16 or key_len > 32 or (key_len & 7) != 0:
            mu.reg_write(UC_X86_REG_EAX, 0x80070057)  # E_INVALIDARG
        else:
            mu.reg_write(UC_X86_REG_EAX, 0)  # Success
            # Store key in context
            for i in range(min(key_len, 32)):
                mu.mem_write(ctx_ptr + 0x18 + i, bytes([key_bytes[i]]))
            mu.mem_write(ctx_ptr + 4, struct.pack('<I', 1))  # key_set flag
            mu.mem_write(ctx_ptr + 0x138, struct.pack('<I', key_len))
        
        mu.reg_write(UC_X86_REG_ESP, esp + 4 + 12)  # ret 0xc
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # corem.dll Ordinal_5 (SetKey16)
    if address == COREM_BASE + 0x12B0:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        ctx_ptr = struct.unpack('<I', mu.mem_read(esp+4, 4))[0]
        key_ptr = struct.unpack('<I', mu.mem_read(esp+8, 4))[0]
        key_len = struct.unpack('<I', mu.mem_read(esp+12, 4))[0]
        
        key_bytes = bytes(mu.mem_read(key_ptr, key_len))
        print(f"[!] corem Ordinal_5 SetKey16 called!")
        print(f"    ctx=0x{ctx_ptr:08x}, key_ptr=0x{key_ptr:08x}, key_len={key_len}")
        print(f"    KEY = {key_bytes.hex()}")
        print(f"    KEY (ASCII) = {repr(key_bytes)}")
        
        hook_returns['aes_key_16'] = key_bytes
        
        if key_len != 16:
            mu.reg_write(UC_X86_REG_EAX, 0x80070057)
        else:
            mu.reg_write(UC_X86_REG_EAX, 1)  # Success (>0)
            mu.mem_write(ctx_ptr + 4, struct.pack('<I', 1))
        
        mu.reg_write(UC_X86_REG_ESP, esp + 4 + 12)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # corem.dll Ordinal_6 (Encrypt/Decrypt)
    if address == COREM_BASE + 0x12D0:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        ctx_ptr = struct.unpack('<I', mu.mem_read(esp+4, 4))[0]
        data_ptr = struct.unpack('<I', mu.mem_read(esp+8, 4))[0]
        data_len = struct.unpack('<I', mu.mem_read(esp+12, 4))[0]
        
        data_bytes = bytes(mu.mem_read(data_ptr, min(data_len, 256)))
        print(f"[!] corem Ordinal_6 Encrypt called!")
        print(f"    data_ptr=0x{data_ptr:08x}, data_len={data_len}")
        print(f"    DATA_IN = {data_bytes[:64].hex()}")
        
        hook_returns['encrypt_input'] = data_bytes
        hook_returns['encrypt_data_ptr'] = data_ptr
        hook_returns['encrypt_data_len'] = data_len
        
        # We'll do the actual AES encryption in Python
        from Crypto.Cipher import AES
        key = hook_returns.get('aes_key_32') or hook_returns.get('aes_key_16')
        if key:
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted = b''
            for i in range(0, data_len, 16):
                block = data_bytes[i:i+16]
                if len(block) == 16:
                    encrypted += cipher.encrypt(block)
            if encrypted:
                mu.mem_write(data_ptr, encrypted[:data_len])
                enc_out = bytes(mu.mem_read(data_ptr, min(data_len, 64)))
                print(f"    DATA_OUT = {enc_out.hex()}")
                hook_returns['session_key'] = enc_out
        
        mu.reg_write(UC_X86_REG_EAX, data_len)
        mu.reg_write(UC_X86_REG_ESP, esp + 4 + 12)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # corem.dll Ordinal_7 (Destroy)
    if address == COREM_BASE + 0x12F0:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        mu.reg_write(UC_X86_REG_EAX, 0)
        mu.reg_write(UC_X86_REG_ESP, esp + 4 + 4)  # ret 4
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # CPKernel helper: malloc (fcn.1001b7da)
    if address == DLL_BASE + 0x1B7DA:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        size = struct.unpack('<I', mu.mem_read(esp+4, 4))[0]
        ptr = heap_alloc(size)
        mu.reg_write(UC_X86_REG_EAX, ptr)
        mu.reg_write(UC_X86_REG_ESP, esp + 8)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # CPKernel helper: memset (fcn.1001b8b0)
    if address == DLL_BASE + 0x1B8B0:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        dst = struct.unpack('<I', mu.mem_read(esp+4, 4))[0]
        val = struct.unpack('<I', mu.mem_read(esp+8, 4))[0] & 0xFF
        size = struct.unpack('<I', mu.mem_read(esp+12, 4))[0]
        mu.mem_write(dst, bytes([val]) * size)
        mu.reg_write(UC_X86_REG_EAX, dst)
        mu.reg_write(UC_X86_REG_ESP, esp + 16)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # CPKernel helper: memcpy (fcn.1001b930) 
    if address == DLL_BASE + 0x1B930:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        dst = struct.unpack('<I', mu.mem_read(esp+4, 4))[0]
        src = struct.unpack('<I', mu.mem_read(esp+8, 4))[0]
        size = struct.unpack('<I', mu.mem_read(esp+12, 4))[0]
        data = bytes(mu.mem_read(src, size))
        mu.mem_write(dst, data)
        mu.reg_write(UC_X86_REG_EAX, dst)
        mu.reg_write(UC_X86_REG_ESP, esp + 16)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # CPKernel helper: free (fcn.1001b6fd)
    if address == DLL_BASE + 0x1B6FD:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        mu.reg_write(UC_X86_REG_EAX, 0)
        mu.reg_write(UC_X86_REG_ESP, esp + 8)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return
    
    # CPKernel helper: stack cookie check (fcn.1001bd8e)
    if address == DLL_BASE + 0x1BD8E:
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret_addr = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        mu.reg_write(UC_X86_REG_ESP, esp + 4)
        mu.reg_write(UC_X86_REG_EIP, ret_addr)
        return

# Instruction counter for debugging
instr_count = [0]
def hook_code_debug(mu, address, size, user_data):
    instr_count[0] += 1
    if instr_count[0] > 50000:
        print(f"[!] Too many instructions ({instr_count[0]}), stopping")
        mu.emu_stop()

def main():
    global heap_ptr
    
    print("=" * 60)
    print("GEM File Key Extractor via x86 Emulation")
    print("=" * 60)
    
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    
    # Map memory regions
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.mem_map(HEAP_BASE, 0x100000)
    mu.mem_map(DATA_BASE, 0x100000)
    
    # Map DLLs
    map_pe(mu, cpkernel_data, DLL_BASE)
    map_pe(mu, corem_data, COREM_BASE)
    
    # Fix import table: CPKernel's corem.dll imports
    # These are at fixed IAT addresses that the code uses
    # sub.corem.dll_Ordinal_3 = 0x10029a36 -> jmp [0x1002a2e4]
    # We need to write the corem function addresses into the IAT
    iat_entries = {
        0x1002A2E4: COREM_BASE + 0x1280,  # Ordinal_3
        0x1002A2E0: COREM_BASE + 0x1290,  # Ordinal_4
        0x1002A2DC: COREM_BASE + 0x12B0,  # Ordinal_5
        0x1002A2D8: COREM_BASE + 0x12D0,  # Ordinal_6
        0x1002A2C4: COREM_BASE + 0x12F0,  # Ordinal_7
    }
    for addr, target in iat_entries.items():
        mu.mem_write(addr, struct.pack('<I', target))
    
    # Write stack cookie value
    mu.mem_write(DLL_BASE + 0x2E0E0, struct.pack('<I', 0xBB40E64E))
    
    # Write "randomkey_nouse" string
    mu.mem_write(DLL_BASE + 0x2A840, b'randomkey_nouse\x00')
    
    # Setup password (wide-char UTF-16LE)
    password = 'yL3@c*Q6xfjGz2TDhxbWCS01ndf'
    pw_wide = password.encode('utf-16-le') + b'\x00\x00'
    
    # Write password to data area
    pw_addr = DATA_BASE
    mu.mem_write(pw_addr, pw_wide)
    
    # Key string (same as password for this player)
    key_addr = DATA_BASE + 0x1000
    mu.mem_write(key_addr, pw_wide)
    
    # Setup stack
    esp = STACK_BASE + STACK_SIZE - 0x1000
    mu.reg_write(UC_X86_REG_ESP, esp)
    
    # Write return address (will be our stop point)
    stop_addr = DATA_BASE + 0x50000
    mu.mem_write(stop_addr, b'\xCC')  # int3
    
    # Push arguments for Ordinal_351(password_wide, key_wide)
    # cdecl: push right-to-left
    esp -= 4
    mu.mem_write(esp, struct.pack('<I', key_addr))   # arg_4ch (key)
    esp -= 4
    mu.mem_write(esp, struct.pack('<I', pw_addr))    # arg_40h (password)
    esp -= 4
    mu.mem_write(esp, struct.pack('<I', stop_addr))  # return address
    mu.reg_write(UC_X86_REG_ESP, esp)
    
    # Hook all the helper functions
    mu.hook_add(UC_HOOK_CODE, hook_code)
    
    # Start address: Ordinal_351
    start_addr = DLL_BASE + 0xC830
    
    print(f"\n[*] Emulating Ordinal_351 at 0x{start_addr:08x}")
    print(f"[*] Password: {password}")
    print(f"[*] Password (wide): {pw_wide[:32].hex()}...")
    print()
    
    try:
        mu.emu_start(start_addr, stop_addr, timeout=10000000, count=100000)
    except UcError as e:
        eip = mu.reg_read(UC_X86_REG_EIP)
        print(f"\n[!] Emulation stopped at 0x{eip:08x}: {e}")
    
    # Get return value
    eax = mu.reg_read(UC_X86_REG_EAX)
    print(f"\n[*] Return value (EAX): 0x{eax:08x}")
    
    if eax and eax > 0x1000:
        # EAX should point to the session key buffer
        try:
            result = bytes(mu.mem_read(eax, 64))
            print(f"[*] Result buffer: {result.hex()}")
            hook_returns['final_result'] = result
        except:
            pass
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    if 'aes_key_32' in hook_returns:
        print(f"AES-256 Key: {hook_returns['aes_key_32'].hex()}")
    if 'aes_key_16' in hook_returns:
        print(f"AES-128 Key: {hook_returns['aes_key_16'].hex()}")
    if 'session_key' in hook_returns:
        print(f"Session Key: {hook_returns['session_key'].hex()}")
    if 'encrypt_input' in hook_returns:
        print(f"Encrypt Input: {hook_returns['encrypt_input'][:64].hex()}")
    
    # Now try to decrypt the video with captured keys
    if hook_returns.get('session_key') or hook_returns.get('aes_key_32') or hook_returns.get('aes_key_16'):
        print("\n[*] Attempting to decrypt .gem file...")
        from Crypto.Cipher import AES
        
        keys_to_try = []
        if 'session_key' in hook_returns:
            sk = hook_returns['session_key']
            keys_to_try.append(('session_key[:16]', sk[:16]))
            keys_to_try.append(('session_key[:32]', sk[:32]))
        if 'aes_key_32' in hook_returns:
            keys_to_try.append(('aes_key_32', hook_returns['aes_key_32']))
        if 'aes_key_16' in hook_returns:
            keys_to_try.append(('aes_key_16', hook_returns['aes_key_16']))
        
        with open('PID-lec1-10. Engineering Maths.gem', 'rb') as f:
            for offset in [0x4000, 0x3d00, 0x317d]:
                for kn, key in keys_to_try:
                    try:
                        f.seek(offset)
                        enc = f.read(16)
                        cipher = AES.new(key, AES.MODE_ECB)
                        dec = cipher.decrypt(enc)
                        print(f"  {kn} @ 0x{offset:x}: {dec.hex()}", end='')
                        if b'ftyp' in dec or dec[:4] in [b'RIFF', b'\x1a\x45\xdf\xa3']:
                            print(" *** VIDEO HEADER FOUND! ***")
                        elif dec[:3] == b'\x00\x00\x00' and dec[3] < 0x80:
                            print(" *** POSSIBLE MP4 ATOM! ***")
                        else:
                            print()
                    except Exception as e:
                        print(f"  {kn} @ 0x{offset:x}: error - {e}")

if __name__ == '__main__':
    main()
