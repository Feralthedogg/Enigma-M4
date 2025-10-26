        .text
        .globl  main
        .extern printf, fflush, Sleep, getchar, fopen, fgets, fclose

# ==============================================================================
# Enigma M4 (Kriegsmarine) — x86-64, GAS (AT&T syntax), Windows / MinGW-w64
#
# Target ABI:
#   - Microsoft x64 (Win64) calling convention.
#     * First four integer/pointer args in RCX, RDX, R8, R9.
#     * Callee must preserve RBX, RBP, RDI, RSI, R12–R15.
#     * Callers reserve 32-byte shadow space on the stack for callees.
#     * For varargs like printf, AL must be 0 before the call.
#
# Build (MinGW-w64):
#   x86_64-w64-mingw32-gcc -O2 -s -x assembler .\enigma_m4.asm -o .\enigma_m4.exe
#
# Runtime:
#   - Prompts for mode: Encrypt (E) or Decrypt (D). [default: E]
#   - Prompts for an input line (max 1023 bytes; stops at CR/LF).
#   - Non-letters pass through unchanged AND DO NOT step the rotors.
#   - Live HUD while typing:
#       E-mode -> "\r[L M R] CT: <text>"
#       D-mode -> "\r[L M R] PT: <text>"
#     (L/M/R = current window letters; updated per keystroke)
#   - Final summary:
#       "[E] <PT> -> <CT>"  or  "[D] <CT> -> <PT>"
#
# Config (YAML):
#   - File: "enigma_setting.yml" (UTF-8; line comments '#', doc-start '---' ignored)
#   - Accepts a UTF-8 BOM (EF BB BF) at the start of any line (after skipping leading spaces/tabs);
#     UTF-16 BOMs are treated as syntax errors.
#   - key: value format (separators: space/tab/comma; full-width colon U+FF1A ok)
#   - Supported keys:
#       rotors: I II III | IV V VI | VII VIII  (order: L M R)
#       rings: A B C
#       positions: A B C
#       greek: B | G  (β or γ)
#       greek_ring: A..Z
#       greek_position: A..Z
#       reflector: B | C (Thin B / Thin C)
#       plugboard: AB CD EF ...  (max 10 pairs)
#
# Notes:
#   - Input a..z is normalized to A..Z; non-letters are emitted as-is and
#     DO NOT trigger stepping.
#   - Greek wheel (β/γ) never steps but its POS/RING offsets affect the path.
#   - Double-stepping implemented (historical M notch logic; ring offset applied).
#   - Reflector tables are symmetric pairings (Thin B / Thin C presets).
#   - Plugboard defaults to identity; can be modified via YAML or plug_pair_idx().
#   - Typing-feel delay: SPEED_MS = 180 ms (Win32 Sleep).
# ==============================================================================


# ------------------------------------------------------------------------------
# Tunables
# ------------------------------------------------------------------------------
.set SPEED_MS, 180             # Inter-keystroke delay in milliseconds
                               # (simulates operator typing rhythm)


# ------------------------------------------------------------------------------
# Rotor structure layout (56 bytes per rotor)
# ------------------------------------------------------------------------------
# [0..25]   ROTOR_W    — forward wiring (maps 0..25 to 0..25)
# [26..51]  ROTOR_INV  — inverse wiring (INV[W[i]] = i)
# [52]      ROTOR_NA   — primary notch position (0..25) or 0xFF if none
# [53]      ROTOR_NB   — secondary notch position (0..25) or 0xFF if none
# [54]      ROTOR_RING — ring setting (Ringstellung), 0..25
# [55]      ROTOR_POS  — current window letter index, 0..25 (A..Z)
# ------------------------------------------------------------------------------

.set ROTOR_W,    0
.set ROTOR_INV,  26
.set ROTOR_NA,   52
.set ROTOR_NB,   53
.set ROTOR_RING, 54
.set ROTOR_POS,  55
.set ROTOR_SIZE, 56


# ------------------------------------------------------------------------------  
# Enigma M4 aggregate layout (E_SIZE = 288 bytes total)  
# ------------------------------------------------------------------------------  
# Offset 0    : Right rotor (R)  
# Offset 56   : Middle rotor (M)  
# Offset 112  : Left rotor (L)  
# Offset 168  : Greek rotor (β/γ; does not step)  
# Offset 224  : Reflector table (26 bytes, symmetric mapping)  
# Offset 250  : Plugboard table (26 bytes, permutation of 0..25)  
#
# NOTE: Total data size = 276 bytes; E_SIZE (288) includes 12 bytes of  
#       alignment/padding for structure spacing and ABI compliance.  
#       If any E_* offset changes, update E_SIZE and all dependent code.  
# ------------------------------------------------------------------------------
.set E_R,    0  
.set E_M,    56  
.set E_L,    112  
.set E_G,    168  
.set E_REF,  224  
.set E_PB,   250  
.set E_SIZE, 288


# ------------------------------------------------------------------------------
# BSS — runtime buffers (zero-initialized by the loader)
# ------------------------------------------------------------------------------
        .comm inbuf,  1024, 16        # input buffer (plaintext / ciphertext)
        .comm outbuf, 1024, 16        # output buffer (after encryption)

# YAML parser temporaries
        .comm yaml_line, 256, 16      # one line from fgets() (NUL-terminated)
        .comm key_buf,   32,  16      # lower-cased key name


# ------------------------------------------------------------------------------
# Data segment — globals and error codes
# ------------------------------------------------------------------------------
        .section .data
mode_ch:        .byte 0        # current mode ('E' or 'D')
err_line:       .long 0        # line number of last YAML error (0 = global)

# YAML parse error codes (negative values => failure)
.set ERR_OK,            0
.set ERR_OPEN,         -1
.set ERR_SYNTAX,       -2
.set ERR_ROTOR_NAME,   -3
.set ERR_GREEK,        -4
.set ERR_REFLECTOR,    -5
.set ERR_RINGS,        -6
.set ERR_POSITIONS,    -7
.set ERR_GREEK_RING,   -8
.set ERR_GREEK_POS,    -9
.set ERR_PLUG_TOKEN,  -10
.set ERR_PLUG_DUP,    -11
.set ERR_PLUG_MANY,   -12
.set ERR_MISSING,     -13


# ------------------------------------------------------------------------------
# Read-only data (rdata) — static tables and strings
# ------------------------------------------------------------------------------
        .section .rdata,"dr"

# --- Reflector pair encodings (Thin B / Thin C) --------------------
# Each 26-byte string represents 13 letter pairs concatenated sequentially:
#   e.g., "AEBNCKDQ..." -> pairs (A–E), (B–N), (C–K), (D–Q), ...
# These are *pair lists*, not direct A->B mappings.
# The ref_setup_pairs() routine later expands them into a 26-byte REF map
# where REF[a] = b and REF[b] = a for each pair.
rfB_pairs:
        .ascii "AEBNCKDQFUGYHWIJLOMPRXSZTV"
rfC_pairs:
        .ascii "ARBDCOEJFNTGHKIVLMPWQZSXUY"


# ------------------------------------------------------------------------------
# YAML loader strings and status messages
# ------------------------------------------------------------------------------
cfg_path:       .asciz "enigma_setting.yml"    # configuration file path
rb_mode:        .asciz "rb"                    # fopen mode (read binary)
fmt_cfg_ok:     .asciz "[SETTINGS] loaded from enigma_setting.yml\n"
fmt_cfg_err:    .asciz "[SETTINGS] parse failed (code %d, line %d). Fix and press ENTER to retry...\n"


# ------------------------------------------------------------------------------
# Rotor tables — static definition of M3/M4 wiring and notches
# ------------------------------------------------------------------------------
        .align 8
rotor_tbl:
        .quad 0                              # index 0 -> unused (null guard)
        .quad rotI_str, rotII_str, rotIII_str, rotIV_str
        .quad rotV_str, rotVI_str, rotVII_str, rotVIII_str
# NOTE: rotor IDs are 1..8 -> rotor_tbl[id] yields the wiring string.
#       Notch table below is 0-based, so code uses (id-1) when indexing it.

# Rotor notch letters (primary NA, secondary NB) per rotor.
# I=Q, II=E, III=V, IV=J, V=Z, VI=Z/M, VII=Z/M, VIII=Z/M
# NB = 0 means “no secondary notch” (later converted to 0xFF sentinel).
rotor_notches_tbl:
        .byte 'Q',  0
        .byte 'E',  0
        .byte 'V',  0
        .byte 'J',  0
        .byte 'Z',  0
        .byte 'Z', 'M'
        .byte 'Z', 'M'
        .byte 'Z', 'M'


# ------------------------------------------------------------------------------
# Console format strings (printf patterns for HUD and result output)
# ------------------------------------------------------------------------------
fmt_live_hdr_E: .asciz "\r[%c %c %c] CT: "
fmt_live_hdr_D: .asciz "\r[%c %c %c] PT: "
fmt_live_ct:    .asciz "%s"
fmt_nl:         .asciz "\n"

fmt_start:     .asciz "[M4] starting...\n"
fmt_mode:      .asciz "Mode [E=encrypt / D=decrypt]: "
fmt_prompt_E:  .asciz "Enter plaintext: "
fmt_prompt_D:  .asciz "Enter ciphertext: "
fmt_result_md: .asciz "[%c] %s -> %s\n"


# ------------------------------------------------------------------------------
# Rotor wiring tables (A=0..Z=25).
# Each string defines the forward wiring W; the inverse table is built at runtime
# such that INV[W[i]] = i. Values are letters 'A'..'Z'.
# ------------------------------------------------------------------------------
rotI_str:    .ascii "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
rotII_str:   .ascii "AJDKSIRUXBLHWTMCQGZNPYFVOE"
rotIII_str:  .ascii "BDFHJLCPRTXVZNYEIWGAKMUSQO"
rotIV_str:   .ascii "ESOVPZJAYQUIRHXLNFTGKDCMWB"
rotV_str:    .ascii "VZBRGITYUPSDNHLXAWMJQOFECK"
rotVI_str:   .ascii "JPGVOUMFYQBENHZRDKASXLICTW"
rotVII_str:  .ascii "NZJHGRCXMYSWBOUFAIVLPEKQDT"
rotVIII_str: .ascii "FKQHTLXOCBJSPDZRAMEWNIUYGV"

# Greek rotors (M4 only). The Greek wheel does not step but uses POS/RING.
beta_str:    .ascii "LEYJVCNIXWPBQMDRTAKZGFUHOS"
gamma_str:   .ascii "FSOKANUERHMBTIYCWLQPZXVGJD"


# ===== Utility: memset-like zero ==============================================
        .text
        .globl  memzero
        .seh_proc memzero
memzero:
        .seh_endprologue              # Win64 SEH: no unwind info needed

        # Synopsis:
        #   void memzero(void* rcx, size_t rdx)
        #
        # Calling convention (Win64 / MS x64):
        #   RCX = destination pointer (uint8_t*)
        #   RDX = number of bytes to zero
        #
        # Clobbers:
        #   RAX
        #
        # Behavior:
        #   Writes zero to len bytes starting at dst. Simple byte loop, no
        #   alignment assumptions, safe for len == 0.

        test %rdx,%rdx                # if (len == 0) return
        jz   .mz_ret
        xor  %rax,%rax                # AL = 0 (byte to store)

.mz_loop:
        movb %al,(%rcx)               # *dst = 0
        inc  %rcx                     # ++dst
        dec  %rdx                     # --len
        jnz  .mz_loop                 # continue until len == 0

.mz_ret:
        ret
        .seh_endproc


# ===== rotor_setup2 ===========================================================
# void rotor_setup2(Rotor* rcx, const char* map, uint8 notchA (r8b), uint8 notchB (r9b))
#
# Purpose:
#   - Build the rotor's forward wiring table W and its inverse table INV from an
#     ASCII mapping string "A..Z".
#   - Store up to two notch positions (primary NA, secondary NB).
#
# Inputs:
#   RCX = pointer to destination Rotor structure
#   RDX = pointer to 26-byte ASCII map ('A'..'Z'), e.g., "EKMFLG..."
#   R8b = notchA as ASCII letter ('A'..'Z') or 0 to disable (-> 0xFF sentinel)
#   R9b = notchB as ASCII letter ('A'..'Z') or 0 to disable (-> 0xFF sentinel)
#
# Postconditions inside *RCX (per ROTOR_* offsets):
#   - W[i]   = map[i] - 'A'
#   - INV[ W[i] ] = i   (bijective inverse of W)
#   - NA = (notchA ? notchA - 'A' : 0xFF)
#   - NB = (notchB ? notchB - 'A' : 0xFF)
#
# Assumptions:
#   - map contains only uppercase A..Z and length ≥ 26.
#   - Rotor memory layout matches the ROTOR_* constants defined above.
#
# Notes:
#   - This routine does not validate that map is a permutation (caller provides
#     trusted tables). If map had duplicates, INV construction would overwrite.
        .globl  rotor_setup2
        .seh_proc rotor_setup2
rotor_setup2:
        .seh_endprologue

        # rdx = map ("EKMFLG..."), r8b = notchA, r9b = notchB
        # rcx = Rotor* (destination)
        # r10d = loop index 0..25, rax = scratch

        xorl %r10d,%r10d              # i = 0
.l1:
        cmpl $26,%r10d                # while (i < 26)
        jge  .l2

        movzbl (%rdx,%r10,1),%eax     # al = map[i] (ASCII)
        subb  $'A',%al                # al = map[i] - 'A'  (0..25)
        movb  %al,ROTOR_W(%rcx,%r10,1)# W[i] = al

        incl  %r10d
        jmp   .l1

.l2:
        # Build inverse wiring: for each i, set INV[ W[i] ] = i
        xorl %r10d,%r10d              # i = 0
.l3:
        cmpl $26,%r10d
        jge  .l4

        movzbl ROTOR_W(%rcx,%r10,1),%eax  # a = W[i]
        movb  %r10b,ROTOR_INV(%rcx,%rax,1)# INV[a] = i

        incl  %r10d
        jmp   .l3

.l4:
        # Store notch A (primary)
        movzbl %r8b,%eax              # eax = notchA (zero-extended)
        testl  %eax,%eax
        jz     .na0                   # if 0 -> NA = 0xFF
        subb   $'A',%al               # 'A'..'Z' -> 0..25
        movb   %al,ROTOR_NA(%rcx)
        jmp    .nb

.na0:
        movb   $0xFF,ROTOR_NA(%rcx)   # no primary notch

.nb:
        # Store notch B (secondary)
        movzbl %r9b,%eax              # eax = notchB (zero-extended)
        testl  %eax,%eax
        jz     .nb0                   # if 0 -> NB = 0xFF
        subb   $'A',%al               # 'A'..'Z' -> 0..25
        movb   %al,ROTOR_NB(%rcx)
        ret

.nb0:
        movb   $0xFF,ROTOR_NB(%rcx)   # no secondary notch
        ret
        .seh_endproc


# ===== ref_setup_sym ==========================================================
# void ref_setup_sym(uint8* rcx, const char* rdx)
#
# Purpose:
#   Initialize a 26-byte reflector lookup table REF from a direct
#   index->partner mapping string (not a pair list). Each position i
#   in the input gives the partner letter for i, as ASCII 'A'..'Z'.
#
# Inputs:
#   RCX = pointer to REF[26] output (each entry 0..25)
#   RDX = pointer to 26 ASCII letters; for each i, rdx[i] gives its partner.
#         Each letter A–Z must appear exactly once across the 26 positions.
#
# Behavior:
#   1) Start with identity mapping REF[i] = i.
#   2) For each i in 0..25:
#        a = rdx[i] - 'A';
#        REF[i] = a; REF[a] = i;   # enforce symmetry
#
# Assumptions:
#   - Input is a full 26-byte mapping table (not a 13-pair list).
#   - Every index 0..25 appears exactly once; no validation performed.
#
# Notes:
#   - Use this for pre-expanded reflector mapping data.
#   - For 13-pair lists (like rfB_pairs / rfC_pairs), use ref_setup_pairs().
        .globl  ref_setup_sym
        .seh_proc ref_setup_sym
ref_setup_sym:
        .seh_endprologue

        # rcx = &REF[0]
        # rdx = 26-char index->partner mapping (ASCII 'A'..'Z')
        # r10d = loop index, rax = scratch

        xorl %r10d,%r10d
# Initialize REF[i] = i
.rs1:
        cmpl $26,%r10d
        jge  .rs2
        movb %r10b,(%rcx,%r10,1)      # REF[i] = i
        incl %r10d
        jmp  .rs1

.rs2:
        xorl %r10d,%r10d
# Apply mapping entries (enforce symmetry)
.rs3:
        cmpl $26,%r10d
        jge  .rs4

        movzbl (%rdx,%r10,1),%eax     # a = pairs[i] (ASCII)
        subb  $'A',%al                # a = a - 'A' (0..25)

        movb  %al,(%rcx,%r10,1)       # REF[i] = a
        movb  %r10b,(%rcx,%rax,1)     # REF[a] = i  (ensure symmetry)

        incl  %r10d
        jmp   .rs3

.rs4:
        ret
        .seh_endproc


# ===== Plugboard ==============================================================
# Plugboard = 26-byte substitution map over A..Z
# Default state:
#   PB[i] = i   (identity mapping)
# Updating with letter pairs (e.g., "AB", "CD") yields swaps:
#   "AB" ⇒ PB[0]=1, PB[1]=0
#   "CD" ⇒ PB[2]=3, PB[3]=2
# …and so on for up to 10 pairs.

        .globl  plug_init
        .seh_proc plug_init
# void plug_init(uint8* rcx)
#
# Purpose:
#   Initialize the plugboard table to the identity mapping.
#
# Inputs:
#   RCX = pointer to plugboard table (26 bytes; entries in 0..25)
#
# Clobbers:
#   R10D
#
# Postcondition:
#   For i in 0..25: PB[i] = i
plug_init:
        .seh_endprologue
        xorl %r10d,%r10d               # r10d = i = 0
.pi1:
        cmpl $26,%r10d                 # while (i < 26)
        jge  .pi2
        movb %r10b,(%rcx,%r10,1)       # PB[i] = i
        incl %r10d
        jmp  .pi1
.pi2:
        ret
        .seh_endproc


        .globl  plug_pair_idx
        .seh_proc plug_pair_idx
# void plug_pair_idx(uint8* rcx, uint8 a (rdx), uint8 b (r8))
#
# Purpose:
#   Swap two plugboard entries by index to realize a letter pair (A↔B, …).
#
# Inputs:
#   RCX = pointer to plugboard table (26 bytes; entries in 0..25)
#   RDX = index a (0..25)
#   R8  = index b (0..25)
#
# Clobbers:
#   RAX, R10D
#
# Behavior:
#   temp=PB[a]; PB[a]=PB[b]; PB[b]=temp;
plug_pair_idx:
        .seh_endprologue
        movzbl (%rcx,%rdx,1),%eax      # temp = PB[a]
        movzbl (%rcx,%r8,1),%r10d      # tmp2 = PB[b]
        movb   %r10b,(%rcx,%rdx,1)     # PB[a] = tmp2
        movb   %al,(%rcx,%r8,1)        # PB[b] = temp
        ret
        .seh_endproc


# ===== rotor_at_notch =========================================================
# int rotor_at_notch(Rotor* rcx)
#
# Purpose:
#   Report whether the current rotor is at a turnover position (primary or
#   secondary notch). This is used by the stepping logic (double-stepping).
#
# Inputs:
#   RCX = Rotor*
#
# Returns:
#   EAX = 1 if ((POS - RING) mod 26) matches NA or NB; otherwise 0.
#
# Notes:
#   POS and RING are combined as in historical machines: window position minus
#   ring offset establishes the mechanical notch position.
        .globl  rotor_at_notch
        .seh_proc rotor_at_notch
rotor_at_notch:
        .seh_endprologue
        movzbl ROTOR_POS(%rcx), %eax   # eax = rotor->POS (window)
        movzbl ROTOR_RING(%rcx), %edx  # edx = rotor->RING (offset)
        subl   %edx, %eax              # eax = POS - RING
        cmpl   $0, %eax
        jge    1f
        addl   $26, %eax               # wrap negative -> +26
1:
        movzbl ROTOR_NA(%rcx), %edx    # edx = notchA
        cmpl   %edx, %eax
        je     2f                      # hit primary notch
        movzbl ROTOR_NB(%rcx), %edx    # edx = notchB
        cmpl   %edx, %eax
        je     2f                      # hit secondary notch
        xorl   %eax, %eax              # not at notch -> return 0
        ret
2:
        movl   $1, %eax                # at notch -> return 1
        ret
        .seh_endproc


# ============================================================
# rotor_fwd(Rotor* rcx, uint32 x)
# ------------------------------------------------------------
# Forward path: right -> left via forward wiring table W.
#
# Formula:
#   t = (x + POS - RING) mod 26
#   y = W[t] - POS + RING    (then wrap back into 0..25)
#
# Inputs:
#   RCX = Rotor*
#   EDX = input letter index (0..25)
#
# Returns:
#   EAX = output letter index (0..25)
#
# Implementation notes:
#   - POS and RING read once for this call.
#   - Mod-26 wrapping done branchlessly with CMOV to avoid mispredicts.
#   - Keeps indices normalized to 0..25 at entry/exit.
# ============================================================

        .globl  rotor_fwd
        .seh_proc rotor_fwd
rotor_fwd:
        .seh_endprologue

        # --- Load static rotor offsets -------------------------------
        movzbl ROTOR_POS(%rcx), %r8d      # r8d = rotor->POS (window position)
        movzbl ROTOR_RING(%rcx), %r9d     # r9d = rotor->RING (ringstellung offset)

        # --- Compute index before wiring ------------------------------
        # t = x + POS - RING
        leal   (%rdx,%r8), %eax           # eax = x + POS
        subl   %r9d, %eax                 # eax = x + POS - RING
        # Range of t ≈ [-25 .. 50]

        # --- Wrap input index to [0, 25] without branches -------------
        # If t >= 26 -> subtract 26
        leal   -26(%rax), %r10d           # r10d = t - 26
        cmpl   $26, %eax
        cmovge %r10d, %eax                # eax = (t >= 26) ? t - 26 : t
        # If t < 0 -> add 26
        leal   26(%rax), %r10d            # r10d = t + 26
        testl  %eax, %eax
        cmovl  %r10d, %eax                # eax = (t < 0) ? t + 26 : t
        # eax now in [0..25]

        # --- Forward wiring lookup ------------------------------------
        movzbl ROTOR_W(%rcx,%rax,1), %eax # eax = W[t] (forward substitution)

        # --- Apply inverse of previous offset -------------------------
        # y = W[t] - POS + RING
        subl   %r8d, %eax                 # subtract POS
        addl   %r9d, %eax                 # add RING
        # Range of y ≈ [-25 .. 50]

        # --- Wrap output index to [0,25] without branches -------------
        leal   -26(%rax), %r10d           # r10d = y - 26
        cmpl   $26, %eax
        cmovge %r10d, %eax                # if y >= 26 -> y -= 26
        leal   26(%rax), %r10d            # r10d = y + 26
        testl  %eax, %eax
        cmovl  %r10d, %eax                # if y < 0  -> y += 26

        # --- Return result --------------------------------------------
        ret
        .seh_endproc


        .globl  rotor_bwd
        .seh_proc rotor_bwd
rotor_bwd:
        .seh_endprologue

        # ============================================================
        # rotor_bwd(Rotor* rcx, uint32 x)
        # ------------------------------------------------------------
        # Backward path: left -> right via inverse wiring table INV.
        #
        # Formula:
        #   t = (x + POS - RING) mod 26
        #   y = INV[t] - POS + RING      (then wrap to 0..25)
        #
        # Inputs:
        #   RCX = Rotor*
        #   EDX = input letter index (0..25)
        #
        # Returns:
        #   EAX = output letter index (0..25)
        #
        # Implementation notes:
        #   - POS/RING read once.
        #   - Mod-26 wraps performed with CMOV (branchless fast path).
        # ============================================================

        # --- Load rotor offsets ------------------------------------
        movzbl ROTOR_POS(%rcx), %r8d       # r8d = rotor->POS
        movzbl ROTOR_RING(%rcx), %r9d      # r9d = rotor->RING

        # --- Compute (x + POS - RING) -------------------------------
        leal   (%rdx,%r8), %eax            # eax = x + POS
        subl   %r9d, %eax                  # eax = x + POS - RING
        # Range of eax ≈ [-25 .. 50]

        # --- Wrap into [0,26) without branches ----------------------
        leal   -26(%rax), %r10d            # r10d = eax - 26
        cmpl   $26, %eax                   # if eax >= 26
        cmovge %r10d, %eax                 #   eax -= 26
        leal   26(%rax), %r10d             # r10d = eax + 26
        testl  %eax, %eax                  # if eax < 0
        cmovl  %r10d, %eax                 #   eax += 26
        # eax now guaranteed in [0..25]

        # --- Backward lookup via INV table --------------------------
        movzbl ROTOR_INV(%rcx,%rax,1), %eax  # eax = INV[x]

        # --- Apply inverse offset (-POS + RING) ---------------------
        subl   %r8d, %eax                  # eax -= POS
        addl   %r9d, %eax                  # eax += RING
        # Range ≈ [-25 .. 50]

        # --- Final wrap to [0,26) branchlessly ----------------------
        leal   -26(%rax), %r10d            # r10d = eax - 26
        cmpl   $26, %eax
        cmovge %r10d, %eax                 # if eax >= 26 -> subtract 26
        leal   26(%rax), %r10d             # r10d = eax + 26
        testl  %eax, %eax
        cmovl  %r10d, %eax                 # if eax < 0  -> add 26

        # --- Return result in eax (0..25) ---------------------------
        ret
        .seh_endproc

# ===== step_m4 ================================================================
# void step_m4(Enigma* rcx)
#
# Purpose:
#   Advance the three moving rotors (R, M, L) according to the M4 stepping
#   rules. The Greek wheel (β/γ) never steps.
#
# Historical double-stepping:
#   - If Middle (M) is at a notch -> step L (and M will also step below).
#   - If Right (R) is at a notch   -> step M.
#   - R always steps every keypress.
#   The notch check uses rotor_at_notch(), which compares (POS - RING) mod 26
#   with each rotor’s NA/NB.
#
# Inputs:
#   RCX = Enigma* (base address of the machine state)
#
# Clobbers:
#   R11, R12, R13, R10D, R9D; uses 32B shadow space
        .globl  step_m4
        .seh_proc step_m4
step_m4:
        push %r12
        .seh_pushreg %r12
        push %r13
        .seh_pushreg %r13
        subq $40,%rsp                    # 32B shadow space + 8B align
        .seh_stackalloc 40
        .seh_endprologue

        # r11 <- &M, r12 <- &R, r13 <- &L (computed once and reused)
        leaq  E_M(%rcx),%r11             # r11 = &enigma->M
        movq  %r11,%rcx
        call  rotor_at_notch
        movl  %eax,%r10d                 # mflag = (M at notch)

        leaq  -E_M+E_R(%r11),%r12        # r12 = &enigma->R
        movq  %r12,%rcx
        call  rotor_at_notch
        movl  %eax,%r9d                  # rflag = (R at notch)

        # If M at notch: step L (double-step trigger)
        testl %r10d,%r10d
        jz    .skip_L
        leaq  -E_M+E_L(%r11),%r13        # r13 = &enigma->L
        movzbl ROTOR_POS(%r13),%eax
        incl  %eax
        cmpl  $26,%eax
        jb    1f
        subl  $26,%eax
1:
        movb  %al,ROTOR_POS(%r13)
.skip_L:

        # Step M if (M at notch) OR (R at notch)
        movl  %r9d,%eax                  # eax = rflag
        orl   %r10d,%eax                 # eax = rflag | mflag
        testl %eax,%eax
        jz    .skip_M
        movzbl ROTOR_POS(%r11),%eax
        incl  %eax
        cmpl  $26,%eax
        jb    2f
        subl  $26,%eax
2:
        movb  %al,ROTOR_POS(%r11)
.skip_M:

        # R always steps
        movzbl ROTOR_POS(%r12),%eax
        incl  %eax
        cmpl  $26,%eax
        jb    3f
        subl  $26,%eax
3:
        movb  %al,ROTOR_POS(%r12)

        addq $40,%rsp
        pop  %r13
        pop  %r12
        ret
        .seh_endproc


# ===== enc_char_m4 ============================================================
# uint8 enc_char_m4(Enigma* rcx, uint8 dl_ascii) -> al_ascii
#
# Purpose:
#   Encrypt/decrypt a single ASCII character using the M4 signal path:
#     1) Normalize to uppercase; non A–Z bytes pass through unchanged.
#     2) Step the three moving rotors (R, M, L) with historical double-stepping.
#     3) Plugboard IN: map x = PB[ch - 'A'] (0..25 domain).
#     4) Forward pass: x = rotor_fwd(R), then M, then L, then Greek (β/γ).
#        (Greek wheel does not step but still offsets/maps like a rotor.)
#     5) Reflect:     x = REF[x]   (Thin B or Thin C reflector).
#     6) Backward pass: x = rotor_bwd(Greek), then L, then M, then R.
#     7) Plugboard OUT: x = PB[x]; return x + 'A' (ASCII).
#
# Calling convention (Win64):
#   RCX = Enigma* (base of machine state)
#   EDX = input character (ASCII)
#   Returns AL = output character (ASCII)
#
# Clobbers:
#   R12, R13, R15 are saved/restored here.
#   Within the body: RAX/RCX/RDX are used for calls/temporaries.
#
# Notes:
#   - Lowercase a..z are promoted to A..Z before processing.
#   - Any non-letter (punctuation, space, digits, etc.) is returned unchanged.
#   - The live HUD/printing is handled by the caller; this routine only maps one byte.
# ==============================================================================
        .globl  enc_char_m4
        .seh_proc enc_char_m4
enc_char_m4:
        # --- Prologue / save non-volatile we use --------------------------------
        push %r12
        .seh_pushreg %r12
        push %r13
        .seh_pushreg %r13
        push %r15
        .seh_pushreg %r15
        subq $32,%rsp                    # Reserve Win64 shadow space (32B)
        .seh_stackalloc 32
        .seh_endprologue

        movq  %rcx,%r12                  # r12 = enigma*
        movl  %edx,%r15d                 # r15d = original input (for non-alpha return)

        # --- Uppercase normalization; early-out for non-letters -----------------
        movl  %edx,%eax                  # al = ch
        cmpb  $'a',%al
        jb    .uc_ok
        cmpb  $'z',%al
        ja    .uc_ok
        subb  $32,%al                    # 'a'..'z' -> 'A'..'Z'
.uc_ok:
        cmpb  $'A',%al
        jb    .nonalpha                  # not a letter -> return original
        cmpb  $'Z',%al
        ja    .nonalpha                  # not a letter -> return original
        movzbl %al,%r13d                 # r13d = normalized 'A'..'Z'

        # --- Step moving rotors (R/M/L) with double-stepping semantics ----------
        movq  %r12,%rcx
        call  step_m4

        # --- Plugboard IN: ASCII -> index -> PB map -----------------------------
        movl  %r13d,%edx
        subl  $'A',%edx                  # to 0..25
        movzbl E_PB(%r12,%rdx,1),%edx    # edx = PB_in[x]

        # --- Forward path: R -> M -> L -> Greek (β/γ; fixed position) ----------
        leaq  E_R(%r12),%rax             # rcx = &R
        movq  %rax,%rcx
        call  rotor_fwd                  # eax = R.fwd(edx)
        movl  %eax,%edx

        leaq  E_M(%r12),%rax             # rcx = &M
        movq  %rax,%rcx
        call  rotor_fwd
        movl  %eax,%edx

        leaq  E_L(%r12),%rax             # rcx = &L
        movq  %rax,%rcx
        call  rotor_fwd
        movl  %eax,%edx

        leaq  E_G(%r12),%rax             # rcx = &Greek (β/γ; non-stepping)
        movq  %rax,%rcx
        call  rotor_fwd                  # eax = 0..25

        # --- Reflector (Thin B/C) ----------------------------------------------
        movzbl E_REF(%r12,%rax,1),%eax   # eax = REF[eax]

        # --- Backward path: Greek -> L -> M -> R -------------------------------
        leaq  E_G(%r12),%rcx             # rcx = &Greek
        movl  %eax,%edx
        call  rotor_bwd
        movl  %eax,%edx

        leaq  E_L(%r12),%rcx             # rcx = &L
        call  rotor_bwd
        movl  %eax,%edx

        leaq  E_M(%r12),%rcx             # rcx = &M
        call  rotor_bwd
        movl  %eax,%edx

        leaq  E_R(%r12),%rcx             # rcx = &R
        call  rotor_bwd                  # eax = 0..25 (final rotor exit)

        # --- Plugboard OUT and convert back to ASCII ---------------------------
        movzbl E_PB(%r12,%rax,1),%eax    # eax = PB_out[eax]
        addb  $'A',%al                   # 0..25 -> 'A'..'Z'

        # --- Epilogue -----------------------------------------------------------
        addq  $32,%rsp
        pop   %r15
        pop   %r13
        pop   %r12
        ret

.nonalpha:
        # Non-letter: return the original input byte unchanged
        movb  %r15b,%al
        addq  $32,%rsp
        pop   %r15
        pop   %r13
        pop   %r12
        ret
        .seh_endproc


# ==== Locals layout (KEEP THE FIRST 32 BYTES FOR SHADOW SPACE) =================
# Stack-frame notes:
#   - Per Win64 ABI, the first 32 bytes at [rsp+0..31] are the caller-reserved
#     "shadow space". We do not use/touch that region.
#   - All parser temporaries (YA_*) start after YA_BASE (= 32).
#
# Local variables (relative to current RSP *after* the prologue's stackalloc):
#   YA_FLAGS  : Bit flags for which required YAML keys have been seen.
#               Bits used:
#                 0 = rotors
#                 1 = greek
#                 2 = reflector
#                 3 = rings
#                 4 = positions
#               On EOF we require (YA_FLAGS & 0x1F) == 0x1F.
#   YA_ROT    : 3 bytes for rotor IDs (L, M, R), values 1..8. Stored in a
#               64-bit slot purely for alignment.
#   YA_RING   : 3 bytes for ring settings (L, M, R), each 0..25 (A..Z).
#   YA_POS    : 3 bytes for starting positions (L, M, R), each 0..25 (A..Z).
#   YA_GAMMA  : 1 byte; 1 = γ (Gamma), 0 = β (Beta).
#   YA_REFC   : 1 byte; 1 = Thin C reflector, 0 = Thin B reflector.
#   YA_GRING  : 1 byte; Greek wheel ring setting (0..25).
#   YA_GPOS   : 1 byte; Greek wheel position      (0..25).
#   YA_PCOUNT : int; number of parsed plugboard pairs (0..10).
#   YA_PAIRS  : up to 10 plugboard pairs × 2 bytes = 20 bytes used.
#               (We allocate a 32-byte block for alignment/slack.)
#   YA_USEDMSK: int; bitmask of letters already used in plugboard (dedupe).
#   YA_TMP0   : int; scratch (e.g., last token value).
#   YA_TMP1   : int; scratch (e.g., token count on current line).
#
        .set YA_BASE,     32            # reserve the first 32B (shadow space)
        .set YA_FLAGS,    YA_BASE+0     # seen-key bitset
        .set YA_ROT,      YA_BASE+8     # rotor L/M/R (3 bytes)
        .set YA_RING,     YA_BASE+16    # ring L/M/R  (3 bytes)
        .set YA_POS,      YA_BASE+24    # pos  L/M/R  (3 bytes)
        .set YA_GAMMA,    YA_BASE+32    # greek_is_gamma (byte)
        .set YA_REFC,     YA_BASE+33    # reflector_is_C  (byte)
        .set YA_GRING,    YA_BASE+34    # greek_ring      (byte)
        .set YA_GPOS,     YA_BASE+35    # greek_pos       (byte)
        .set YA_PCOUNT,   YA_BASE+40    # plug_count (int)
        .set YA_PAIRS,    YA_BASE+48    # plug_pairs[20] (10×2 bytes)
        .set YA_USEDMSK,  YA_BASE+80    # used-letters bitmask (int)
        .set YA_TMP0,     YA_BASE+84    # scratch token (int)
        .set YA_TMP1,     YA_BASE+88    # scratch counter (int)

# ------------------------------------------------------------------------------
# int yaml_apply(const char* path, void* e, int* errline)
#   RCX = path (C string), RDX = e* (Enigma*), R8 = &errline (int*).
#   Returns EAX = 0 on success, or a negative ERR_* code on failure.
#
# Purpose:
#   - Open YAML settings file (binary mode "rb").
#   - Read and parse line by line into YA_* locals (staging).
#   - Normalize and validate tokens (BOM, keys, ranges, counts, dedupe).
#   - On error: set *errline to the failing line number and return ERR_*.
#               (For open/missing, errline is set to 0.)
#   - On success: materialize settings into the Enigma* state at RDX.
#
# Notes:
#   - We call libc (fopen/fgets/fclose/printf), so all callee-saved registers
#     we use are preserved. The frame also reserves the ABI shadow space.
# ------------------------------------------------------------------------------
        .globl  yaml_apply
        .seh_proc yaml_apply
yaml_apply:
        # ========== Save callee-saved registers per Win64 ======================
        push %rbx                        # FILE* and general scratch
        .seh_pushreg %rbx
        push %r12                        # e* (Enigma*)
        .seh_pushreg %r12
        push %r13                        # &errline
        .seh_pushreg %r13
        push %r14                        # path
        .seh_pushreg %r14
        push %r15                        # lineno / counters
        .seh_pushreg %r15
        push %rdi                        # scratch (callee-saved)
        .seh_pushreg %rdi
        push %rsi                        # scratch (callee-saved)
        .seh_pushreg %rsi
        push %rbp                        # optional frame base
        .seh_pushreg %rbp

        # Allocate locals:
        #   136 bytes total = 32B shadow (kept unused) + YA_* area.
        subq $136,%rsp
        .seh_stackalloc 136
        .seh_endprologue

        # --------- Stash arguments in preserved registers ---------------------
        mov  %rcx, %r14                 # r14 = path
        mov  %rdx, %r12                 # r12 = e*
        mov  %r8,  %r13                 # r13 = &errline

        # --------- Open file: fopen(path, "rb") -------------------------------
        leaq rb_mode(%rip), %rdx        # rdx = "rb"
        mov  %r14, %rcx                 # rcx = path
        call fopen
        test %rax, %rax
        jnz  .fp_ok                     # success -> rax = FILE*

        # fopen failed: errline = 0, return ERR_OPEN
        movl $0,(%r13)                  # *errline = 0
        movl $ERR_OPEN,%eax             # EAX = -1
        jmp  .ya_ret_err

.fp_ok:
        mov  %rax, %rbx                 # rbx = FILE*

        # ==== Initialize all YA_* locals (do NOT touch [rsp+0..31]) ===========
        # Zeroing the 8-byte slots also clears the embedded byte fields.
        xor  %rax,%rax
        movq %rax, YA_FLAGS(%rsp)       # seen-key flags = 0
        movq %rax, YA_ROT(%rsp)         # rotor L/M/R = 0
        movq %rax, YA_RING(%rsp)        # rings L/M/R = 0
        movq %rax, YA_POS(%rsp)         # positions L/M/R = 0
        movq %rax, YA_GAMMA(%rsp)       # greek/reflector bytes cleared
        movq %rax, YA_PCOUNT(%rsp)      # plug_count = 0
        movq %rax, YA_PAIRS(%rsp)       # clear pairs[0..7]
        movq %rax, YA_PAIRS+8(%rsp)
        movq %rax, YA_PAIRS+16(%rsp)
        movq %rax, YA_USEDMSK(%rsp)     # plugboard used-letters mask = 0

        xorl %r15d,%r15d                # lineno = 0

        # From here on:
        #   fgets -> strip comments -> trim -> handle BOM/doc-start
        #   -> split key:value (ASCII ':' or full-width U+FF1A)
        #   -> lowercase key into key_buf
        #   -> advance r9 to start of value (skip leading WS)
        #   -> per-key parse/validate, set YA_FLAGS bits
        #   -> on error: set *errline = lineno and bail
        #   -> on EOF: check required keys, then materialize into *e


# ==== Line loop ===============================================================
# One line at a time:
#   - Read into yaml_line
#   - Remove inline comments after '#'
#   - Trim trailing whitespace/CR/LF and skip leading spaces/tabs
#   - Handle BOM and YAML document start ('---')
#   - Find the key/value separator (':' or U+FF1A)
#   - Copy the key (trimmed) to key_buf in lowercase
#   - Set r9 to the beginning of the value (after skipping spaces/tabs)
.y_read:
        # fgets(yaml_line, 256, fp)
        leaq yaml_line(%rip),%rcx       # rcx = &yaml_line[0]
        mov  $256,%edx                  # edx = buffer size
        mov  %rbx,%r8                   # r8  = FILE* fp
        call fgets
        test %rax,%rax                  # NULL on EOF / error
        jnz  .got_line
        jmp  .eof

.got_line:
        incl %r15d                      # ++lineno

        # --- Strip end-of-line comments: first '#' terminates the line --------
        leaq yaml_line(%rip),%rdi       # rdi = p = start of line
.cmt_scan:
        movb (%rdi),%al                 # read char
        test %al,%al                    # NUL? end of string
        jz   .after_cmt
        cmpb $'#',%al                   # comment start?
        je   .cut_here
        inc  %rdi
        jmp  .cmt_scan

.cut_here:
        movb $0,(%rdi)                  # terminate string at '#'

.after_cmt:

        # --- Trim trailing spaces/tabs and CR/LF -------------------------------
        leaq yaml_line(%rip),%rdi       # rdi = start
        mov  %rdi,%rsi                  # rsi = scan forward to NUL

.find0:
        movb (%rsi),%al
        test %al,%al
        jz   .backtrim                  # reached NUL
        inc  %rsi
        jmp  .find0

.backtrim:
        cmp  %rsi,%rdi                  # empty line?
        je   .next_line
        dec  %rsi                       # rsi = last non-NUL char

.bt1:
        cmpb $' ',(%rsi)
        je   .z0
        cmpb $'\t',(%rsi)
        je   .z0
        cmpb $'\r',(%rsi)
        je   .z0
        cmpb $'\n',(%rsi)
        jne  .after_trim                # stop when non-WS/CR/LF
.z0:
        movb $0,(%rsi)                  # trim it
        cmp  %rsi,%rdi
        je   .after_trim                # line became empty
        dec  %rsi
        jmp  .bt1

.after_trim:
        # --- Skip leading spaces/tabs -----------------------------------------
        leaq yaml_line(%rip),%rsi       # rsi = (possibly trimmed) start
.lskip:
        movb (%rsi),%al
        cmpb $' ',%al
        je   .ls1
        cmpb $'\t',%al
        jne  .ls_done
.ls1:
        inc  %rsi
        jmp  .lskip

.ls_done:
        # --- Reject UTF-16 BOMs (FE FF or FF FE) ------------------------------
        cmpb $0xFF, (%rsi)              # 0xFF 0xFE (UTF-16 LE BOM)?
        jne  1f
        cmpb $0xFE, 1(%rsi)
        jne  1f
        movl %r15d,(%r13)               # *errline = lineno
        movl $ERR_SYNTAX,%eax
        jmp  .fail_close
1:
        cmpb $0xFE, (%rsi)              # 0xFE 0xFF (UTF-16 BE BOM)?
        jne  .no_bom
        cmpb $0xFF, 1(%rsi)
        jne  .no_bom
        movl %r15d,(%r13)
        movl $ERR_SYNTAX,%eax
        jmp  .fail_close

        # --- Accepts a UTF-8 BOM (EF BB BF) at the start of any line after skipping leading spaces/tabs (not limited to file start) -----------
        cmpb $0xEF,(%rsi)
        jne  .no_bom
        cmpb $0xBB,1(%rsi)
        jne  .no_bom
        cmpb $0xBF,2(%rsi)
        jne  .no_bom
        add  $3,%rsi                    # skip BOM
.no_bom:

        # --- Skip YAML document start line '---' -------------------------------
        cmpb $'-',(%rsi)
        jne  .after_bof
        cmpb $'-',1(%rsi)
        jne  .after_bof
        cmpb $'-',2(%rsi)
        jne  .after_bof
        jmp  .next_line                 # ignore the '---' line

.after_bof:
        movb  (%rsi), %al               # empty after trims?
        test  %al, %al
        jz    .next_line                # blank -> read next

        # --- Find the key:value separator (':' or full-width U+FF1A) ----------
        mov   %rsi, %rdi                # rdi scans forward from current pos
        jmp   .findc

.findc:
        movb (%rdi),%al
        test %al,%al
        jz   .next_line                 # malformed (no separator)
        cmpb $':',%al
        je   .gotc_ascii

        # Full-width colon U+FF1A (UTF-8: EF BC 9A)
        cmpb $0xEF,%al
        jne  .fc_next
        cmpb $0xBC,1(%rdi)
        jne  .fc_next
        cmpb $0x9A,2(%rdi)
        jne  .fc_next
        lea  3(%rdi), %r9        # r9 = start of value (3 bytes after colon)
        jmp  .gotc               # rdi is exactly where the colon starts -> the end of the key is exactly right before the colon

.fc_next:
        inc  %rdi
        jmp  .findc

.gotc_ascii:
        leaq 1(%rdi), %r9               # r9 = value start after ':' (ASCII)
        jmp  .gotc

.gotc:
        # Trim trailing spaces/tabs from the key slice [rsi..rdi)
        mov     %rdi, %rax
        dec     %rax

.ktrim:
        cmp     %rax, %rsi
        jb      .ktrim_done
        movb    (%rax), %al
        cmpb    $' ', %al
        je      .ktrim_step
        cmpb    $'\t', %al
        jne     .ktrim_done
.ktrim_step:
        dec     %rax
        jmp     .ktrim
.ktrim_done:
        leaq    1(%rax), %rdi           # rdi = key_end (exclusive)

        # Copy key to key_buf in lowercase
        leaq key_buf(%rip), %rcx        # rcx = dest (key_buf)
        mov  %rcx, %r8                  # r8  = write cursor
        mov  %rsi, %r10                 # r10 = src cursor
.kcp:
        cmp  %r10, %rdi                 # while (src < key_end)
        je   .kdone
        movb (%r10), %al                # read byte
        cmpb $'A', %al                  # ASCII A..Z -> make lowercase
        jb   .kp
        cmpb $'Z', %al
        ja   .kp
        addb $32, %al
.kp:
        movb %al, (%r8)                 # write
        inc  %r8                        # dest++
        inc  %r10                       # src++
        jmp  .kcp
.kdone:
        movb $0, (%r8)                  # NUL-terminate key_buf

        # Skip leading spaces/tabs before the value (r9 points after ':')
.vskip:
        movb (%r9),%al
        cmpb $' ',%al
        je   .vs1
        cmpb $'\t',%al
        jne  .vready                    # first non-space/tab: value starts
.vs1:
        inc  %r9
        jmp  .vskip

.vready:
        # ==== Key-dispatch =====================================================
        # We have:
        #   - key_buf: lowercased key text (NUL-terminated)
        #   - r9     : pointer to the beginning of the value text (leading WS skipped)
        # Below we branch on the key and parse the corresponding value.

        leaq key_buf(%rip),%rcx         # rcx = key_buf (lowercased key text)

        # ----------------------------------------------------------------------
        # key == "rotors"
        #   Expected value:
        #     Three Roman numerals for (L M R), e.g. "I II III"
        #   Separators accepted:
        #     space, tab, comma
        #   Roman parser supports:
        #     I, II, III, IV, V, VI, VII, VIII  (-> 1..8)
        #   Side effects:
        #     - YA_ROT[0..2] = (L, M, R) rotor IDs (1..8)
        #     - Sets YA_FLAGS bit0 when parsed successfully
        #     - On error: sets *errline and returns ERR_ROTOR_NAME
        # ----------------------------------------------------------------------
        mov  %rcx,%rbp
        movb (%rbp),%al
        cmpb $'r',%al; jne .chk_greek
        cmpb $'o',1(%rbp); jne .chk_greek
        cmpb $'t',2(%rbp); jne .chk_greek
        cmpb $'o',3(%rbp); jne .chk_greek
        cmpb $'r',4(%rbp); jne .chk_greek
        cmpb $'s',5(%rbp); jne .chk_greek
        movb 6(%rbp),%al
        test %al,%al                     # ensure exact match "rotors\0"
        jne  .chk_greek

        # --- Parse rotors: 3 Roman tokens in order (L M R) --------------------
        mov  %r9,%rdi                    # rdi = p = start of value text
        xorl %eax,%eax
        movb %al, YA_ROT(%rsp)           # clear L slot
        movb %al, YA_ROT+1(%rsp)         # clear M slot
        movb %al, YA_ROT+2(%rsp)         # clear R slot
        movl $0,%edx                     # edx = count of parsed tokens (0..3)

.rtok_lp:
        # Skip separators (space, tab, comma); stop at NUL -> end of line
        movb (%rdi),%al
        test %al,%al
        jz   .rt_end
        cmpb $' ',%al;  je .rt_adv
        cmpb $'\t',%al; je .rt_adv
        cmpb $',',%al;  je .rt_adv
        jmp  .rt_read

.rt_adv:
        inc %rdi
        jmp .rtok_lp

.rt_read:
        # Normalize the token's first letter to uppercase (allow lowercase)
        movb (%rdi),%al
        cmpb $'a',%al; jb .r0
        cmpb $'z',%al; ja .r0
        subb $32,%al                     # 'a'..'z' -> 'A'..'Z'

.r0:
        # Dispatch by first Roman letter: 'I' or 'V'
        cmpb $'I',%al; je .tok_I
        cmpb $'V',%al; je .tok_V
        jmp  .rot_bad                    # anything else -> invalid

# ----------------------------- Roman: starts with I ---------------------------
# Supports: I, II, III, IV
# Note: Lowercase 'i' is accepted, but 'v' in "IV"/"iv" is not recognized.
#       Only uppercase 'V' works in the subtractive form.
.tok_I:
        mov  %rdi,%rsi                   # rsi = scan pointer
        movl $0,%ecx                     # ecx = count of consecutive 'I'/'i'

.ii_lp:
        movb (%rsi),%al
        cmpb $'i',%al;  je .ii_low       # allow lowercase 'i'
        cmpb $'I',%al;  jne .ii_done     # break if not 'I'/'i'
.ii_low:
        inc %ecx                         # ++count of I's
        inc %rsi
        jmp .ii_lp

.ii_done:
        # Check subtractive form "IV" (i.e., 'I' followed by 'V')
        cmpb $'V',(%rdi,%rcx,1)          # look at char after the I-run
        jne  .no_IV
        movl $4,%eax                     # token value = 4
        leaq 1(%rdi,%rcx,1),%rdi         # advance past 'I...' and the 'V'
        jmp  .tok_ok

.no_IV:
        # Otherwise, accept I, II, or III only
        cmp  $1,%ecx; je .i1
        cmp  $2,%ecx; je .i2
        cmp  $3,%ecx; je .i3
        jmp  .rot_bad                    # more than 3 I's is invalid

.i1:
        movl $1,%eax
        add  $1,%rdi                     # consume "I"
        jmp .tok_ok
.i2:
        movl $2,%eax
        add  $2,%rdi                     # consume "II"
        jmp .tok_ok
.i3:
        movl $3,%eax
        add  $3,%rdi                     # consume "III"
        jmp .tok_ok

# ----------------------------- Roman: starts with V ---------------------------
# Note: The leading 'V' is case-insensitive (both v and V are allowed).
# The trailing 'I's are case-insensitive.
# However, 'IV' detection only capitalizes the 'V' in .tok_I (so Iv/iv is not recognized as 4).
.tok_V:
        movl $5,%eax
        inc  %rdi                        # consume 'V'

        # Optional 'I' (-> 6)
        mov    (%rdi), %r10b
        cmpb   $'I', %r10b
        je     .v_i1
        cmpb   $'i', %r10b
        jne    .tok_ok                   # plain 'V' (5) if not 'I'/'i'

.v_i1:
        inc  %rdi
        movl $6, %eax                    # we have "VI"

        # Optional second 'I' (-> 7)
        mov    (%rdi), %r10b
        cmpb   $'I', %r10b
        je     .v_i2
        cmpb   $'i', %r10b
        jne    .tok_ok

.v_i2:
        inc  %rdi
        movl $7, %eax                    # we have "VII"

        # Optional third 'I' (-> 8)
        mov    (%rdi), %r10b
        cmpb   $'I', %r10b
        je     .v_i3
        cmpb   $'i', %r10b
        jne    .tok_ok

.v_i3:
        inc  %rdi
        movl $8, %eax                    # "VIII"
        jmp  .tok_ok

# ----------------------------- Common success path ----------------------------
# On entry:
#   - eax = parsed value (1..8)
#   - rdi advanced past token
# Side effect:
#   - Store into YA_ROT[L/M/R] according to current token count (edx)
.tok_ok:
        movl %eax, YA_TMP0(%rsp)      # token
        movl %edx, YA_TMP1(%rsp)      # count

        cmpl $0,%edx; je .savL
        cmpl $1,%edx; je .savM
        cmpl $2,%edx; je .savR
        jmp  .rt_end                   # ignore extras (shouldn't happen)

.savL:
        movb %al, YA_ROT(%rsp)        # L = token
        incl %edx
        movl %edx, YA_TMP1(%rsp)
        jmp  .rtok_lp

.savM:
        movb %al, YA_ROT+1(%rsp)      # M = token
        incl %edx
        movl %edx, YA_TMP1(%rsp)
        jmp  .rtok_lp

.savR:
        movb %al, YA_ROT+2(%rsp)      # R = token
        incl %edx
        movl %edx, YA_TMP1(%rsp)
        jmp  .rtok_lp

# --- Rotor parse error path ---------------------------------------------------
.rot_bad:
        movl %r15d,(%r13)              # *errline = lineno
        movl $ERR_ROTOR_NAME,%eax      # invalid rotor token/name
        jmp  .fail_close
        
.rt_end:
        # Must have exactly 3 rotor tokens
        cmpl $3,%edx
        jne  .rot_bad

        # === Sanity: each rotor must be in [1..8] ===
        movzbl YA_ROT(%rsp),   %eax
        test  %al,%al
        jz    .rot_bad
        cmpb  $8,%al
        ja    .rot_bad

        movzbl YA_ROT+1(%rsp), %eax
        test  %al,%al
        jz    .rot_bad
        cmpb  $8,%al
        ja    .rot_bad

        movzbl YA_ROT+2(%rsp), %eax
        test  %al,%al
        jz    .rot_bad
        cmpb  $8,%al
        ja    .rot_bad
        # ============================================

        movq YA_FLAGS(%rsp),%rax
        orq  $1,%rax                    # set bit0: have rotors
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line


# ----------------------------------------------------------------------
# key == "greek"
#   Expected value:
#     Single letter 'B' (Beta) or 'G' (Gamma), case-insensitive.
#   Side effects:
#     - YA_GAMMA = 1 if 'G', else 0 for 'B'
#     - Sets YA_FLAGS bit1
#   On error:
#     ERR_GREEK
# ----------------------------------------------------------------------
.chk_greek:
        mov  %rcx,%rbp
        movb (%rbp),%al
        cmpb $'g',%al; jne .chk_ref
        cmpb $'r',1(%rbp); jne .chk_ref
        cmpb $'e',2(%rbp); jne .chk_ref
        cmpb $'e',3(%rbp); jne .chk_ref
        cmpb $'k',4(%rbp); jne .chk_ref
        movb 5(%rbp),%al
        test %al,%al
        jne  .chk_ref
        movb (%r9),%al
        cmpb $'a',%al; jb .g_upd
        cmpb $'z',%al; ja .g_upd
        subb $32,%al                     # force uppercase if 'a'..'z'
.g_upd:
        cmpb $'G',%al; je .is_gamma
        cmpb $'B',%al; je .is_beta
        movl %r15d,(%r13)
        movl $ERR_GREEK,%eax
        jmp  .fail_close
.is_gamma:
        movb $1,YA_GAMMA(%rsp)          # Gamma
        jmp  .g_ok
.is_beta:
        movb $0,YA_GAMMA(%rsp)          # Beta
.g_ok:
        movq YA_FLAGS(%rsp),%rax
        orq  $2,%rax                    # set bit1: have greek
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line

# ----------------------------------------------------------------------
# key == "reflector"
#   Expected value:
#     'B' or 'C' (Thin B / Thin C), case-insensitive.
#   Parsing approach:
#     Default to B; if any 'c'/'C' is found in the value text, choose C.
#   Side effects:
#     - YA_REFC = 1 for Thin C, 0 for Thin B
#     - Sets YA_FLAGS bit2
# ----------------------------------------------------------------------
.chk_ref:
        mov  %rcx,%rbp
        movb (%rbp),%al
        cmpb $'r',%al;    jne .chk_rings
        cmpb $'e',1(%rbp);jne .chk_rings
        cmpb $'f',2(%rbp);jne .chk_rings
        cmpb $'l',3(%rbp);jne .chk_rings
        cmpb $'e',4(%rbp);jne .chk_rings
        cmpb $'c',5(%rbp);jne .chk_rings
        cmpb $'t',6(%rbp);jne .chk_rings
        cmpb $'o',7(%rbp);jne .chk_rings
        cmpb $'r',8(%rbp);jne .chk_rings
        movb 9(%rbp),%al
        test %al,%al
        jne  .chk_rings
        movb $0,YA_REFC(%rsp)           # default to Thin B
        mov  %r9,%rsi
.rf_s:  movb (%rsi),%al
        test %al,%al
        jz   .rf_done
        cmpb $'c',%al; je .rf_c
        cmpb $'C',%al; je .rf_c
        inc  %rsi
        jmp  .rf_s
.rf_c:  movb $1,YA_REFC(%rsp)           # Thin C if any 'c'/'C' seen
.rf_done:
        movq YA_FLAGS(%rsp),%rax
        orq  $4,%rax                    # set bit2: have reflector
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line

# ----------------------------------------------------------------------
# key == "rings"
#   Expected value:
#     Three letters A..Z for (L M R) ring settings (Ringstellung).
#   Behavior:
#     Letters are case-insensitive and mapped to 0..25.
#   Side effects:
#     - YA_RING[0..2] = L,M,R (0..25)
#     - Sets YA_FLAGS bit3
#   On error:
#     ERR_RINGS (not exactly three valid letters)
# ----------------------------------------------------------------------
.chk_rings:
        mov  %rcx,%rbp
        cmpb $'r',(%rbp); jne .chk_greek_ring
        cmpb $'i',1(%rbp); jne .chk_greek_ring
        cmpb $'n',2(%rbp); jne .chk_greek_ring
        cmpb $'g',3(%rbp); jne .chk_greek_ring
        cmpb $'s',4(%rbp); jne .chk_greek_ring
        movb 5(%rbp),%al
        test %al,%al
        jne  .chk_greek_ring
        mov  %r9,%rsi
        xorl %ecx,%ecx                   # token index 0..2
.rg_lp:
        movb (%rsi),%al
        test %al,%al
        jz   .rg_done
        cmpb $'A',%al; jb .rg_adv
        cmpb $'Z',%al; jbe .rg_cap
        cmpb $'a',%al; jb .rg_adv
        cmpb $'z',%al; ja .rg_adv
        subb $32,%al                     # to uppercase

.rg_cap:
        subb $'A',%al                    # 'A'..'Z' -> 0..25
        cmpb $25,%al; ja .rg_adv
        cmp  $0,%ecx; je .rgL
        cmp  $1,%ecx; je .rgM
        cmp  $2,%ecx; je .rgR
        jmp  .rg_adv
.rgL:   movb %al,YA_RING(%rsp);     incl %ecx; jmp .rg_adv
.rgM:   movb %al,YA_RING+1(%rsp);   incl %ecx; jmp .rg_adv
.rgR:   movb %al,YA_RING+2(%rsp);   incl %ecx; jmp .rg_adv
.rg_adv:
        inc  %rsi
        jmp  .rg_lp

.rg_done:
        cmp  $3,%ecx
        jne  .rings_err                 # need exactly 3 ring tokens
        movq YA_FLAGS(%rsp),%rax
        orq  $8,%rax                    # set bit3: have rings
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line

.rings_err:
        movl %r15d,(%r13)
        movl $ERR_RINGS,%eax
        jmp  .fail_close

# ----------------------------------------------------------------------
# key == "greek_ring"
#   Expected value:
#     Single letter A..Z (case-insensitive) -> 0..25
#   Side effects:
#     - YA_GRING = value
#   On error:
#     ERR_GREEK_RING
# ----------------------------------------------------------------------
.chk_greek_ring:
        mov  %rcx,%rbp
        cmpb $'g',(%rbp); jne .chk_positions
        cmpb $'r',1(%rbp); jne .chk_positions
        cmpb $'e',2(%rbp); jne .chk_positions
        cmpb $'e',3(%rbp); jne .chk_positions
        cmpb $'k',4(%rbp); jne .chk_positions
        cmpb $'_',5(%rbp); jne .chk_positions
        cmpb $'r',6(%rbp); jne .chk_positions
        cmpb $'i',7(%rbp); jne .chk_positions
        cmpb $'n',8(%rbp); jne .chk_positions
        cmpb $'g',9(%rbp); jne .chk_positions
        movb 10(%rbp),%al
        test %al,%al
        jne  .chk_positions
        movb (%r9),%al
        cmpb $'a',%al; jb .gr_ok
        cmpb $'z',%al; ja .gr_ok
        subb $32,%al                     # to uppercase
.gr_ok:
        subb $'A',%al
        cmpb $25,%al; ja .gr_err
        movb %al,YA_GRING(%rsp)
        jmp  .next_line

.gr_err:
        movl %r15d,(%r13)
        movl $ERR_GREEK_RING,%eax
        jmp  .fail_close

# ----------------------------------------------------------------------
# key == "positions"
#   Expected value:
#     Three letters A..Z for (L M R) window positions (case-insensitive).
#   Behavior:
#     Letters map to 0..25.
#   Side effects:
#     - YA_POS[0..2] = L,M,R
#     - Sets YA_FLAGS bit4
#   On error:
#     ERR_POSITIONS (not exactly three valid letters)
# ----------------------------------------------------------------------
.chk_positions:
        mov  %rcx,%rbp
        cmpb $'p',(%rbp); jne .chk_greek_pos
        cmpb $'o',1(%rbp); jne .chk_greek_pos
        cmpb $'s',2(%rbp); jne .chk_greek_pos
        cmpb $'i',3(%rbp); jne .chk_greek_pos
        cmpb $'t',4(%rbp); jne .chk_greek_pos
        cmpb $'i',5(%rbp); jne .chk_greek_pos
        cmpb $'o',6(%rbp); jne .chk_greek_pos
        cmpb $'n',7(%rbp); jne .chk_greek_pos
        cmpb $'s',8(%rbp); jne .chk_greek_pos
        movb 9(%rbp),%al
        test %al,%al
        jne  .chk_greek_pos
        mov  %r9,%rsi
        xorl %ecx,%ecx                   # token index 0..2
.ps_lp:
        movb (%rsi),%al
        test %al,%al
        jz   .ps_done
        cmpb $'A',%al; jb .ps_adv
        cmpb $'Z',%al; jbe .ps_cap
        cmpb $'a',%al; jb .ps_adv
        cmpb $'z',%al; ja .ps_adv
        subb $32,%al                     # to uppercase
.ps_cap:
        subb $'A',%al                    # -> 0..25
        cmpb $25,%al; ja .ps_adv
        cmp  $0,%ecx; je .psL
        cmp  $1,%ecx; je .psM
        cmp  $2,%ecx; je .psR
        jmp  .ps_adv
.psL:   movb %al,YA_POS(%rsp);     incl %ecx; jmp .ps_adv
.psM:   movb %al,YA_POS+1(%rsp);   incl %ecx; jmp .ps_adv
.psR:   movb %al,YA_POS+2(%rsp);   incl %ecx; jmp .ps_adv
.ps_adv:
        inc  %rsi
        jmp  .ps_lp

.ps_done:
        cmp  $3,%ecx
        jne  .pos_err
        movq YA_FLAGS(%rsp),%rax
        orq  $16,%rax                   # set bit4: have positions
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line

.pos_err:
        movl %r15d,(%r13)
        movl $ERR_POSITIONS,%eax
        jmp  .fail_close

# ----------------------------------------------------------------------
# key == "greek_position"
#   Expected value:
#     Single letter A..Z (case-insensitive) -> 0..25
#   Side effects:
#     - YA_GPOS = value
#   On error:
#     ERR_GREEK_POS
# ----------------------------------------------------------------------
.chk_greek_pos:
        mov  %rcx,%rbp
        cmpb $'g',(%rbp); jne .chk_plug
        cmpb $'r',1(%rbp); jne .chk_plug
        cmpb $'e',2(%rbp); jne .chk_plug
        cmpb $'e',3(%rbp); jne .chk_plug
        cmpb $'k',4(%rbp); jne .chk_plug
        cmpb $'_',5(%rbp); jne .chk_plug
        cmpb $'p',6(%rbp); jne .chk_plug
        cmpb $'o',7(%rbp); jne .chk_plug
        cmpb $'s',8(%rbp); jne .chk_plug
        cmpb $'i',9(%rbp); jne .chk_plug
        cmpb $'t',10(%rbp); jne .chk_plug
        cmpb $'i',11(%rbp); jne .chk_plug
        cmpb $'o',12(%rbp); jne .chk_plug
        cmpb $'n',13(%rbp); jne .chk_plug
        movb 14(%rbp),%al
        test %al,%al
        jne  .chk_plug
        movb (%r9),%al
        cmpb $'a',%al; jb .gp_ok
        cmpb $'z',%al; ja .gp_ok
        subb $32,%al                     # to uppercase
.gp_ok:
        subb $'A',%al
        cmpb $25,%al; ja .gp_err
        movb %al,YA_GPOS(%rsp)
        jmp  .next_line

.gp_err:
        movl %r15d,(%r13)
        movl $ERR_GREEK_POS,%eax
        jmp  .fail_close

# ----------------------------------------------------------------------
# key == "plugboard"
#   Expected value:
#     Zero or more disjoint letter pairs like "AB CD EF", case-insensitive.
#     Separators allowed: spaces, tabs, commas.
#   Constraints:
#     - Letters map A..Z -> 0..25
#     - A pair must be two different letters (e.g., 'AA' invalid)
#     - Each letter may appear at most once overall
#     - Up to 10 pairs max (Enigma limit)
#   Side effects:
#     - YA_PCOUNT = number of pairs
#     - YA_PAIRS[2*i + {0,1}] = indices 0..25 for each pair
#     - YA_USEDMSK bitmask tracks used letters
#   On error:
#     ERR_PLUG_TOKEN  (invalid token)
#     ERR_PLUG_DUP    (letter reused)
#     ERR_PLUG_MANY   (>10 pairs)
# ----------------------------------------------------------------------
.chk_plug:
        mov  %rcx,%rbp
        cmpb $'p',(%rbp); jne .next_line
        cmpb $'l',1(%rbp); jne .next_line
        cmpb $'u',2(%rbp); jne .next_line
        cmpb $'g',3(%rbp); jne .next_line
        cmpb $'b',4(%rbp); jne .next_line
        cmpb $'o',5(%rbp); jne .next_line
        cmpb $'a',6(%rbp); jne .next_line
        cmpb $'r',7(%rbp); jne .next_line
        cmpb $'d',8(%rbp); jne .next_line
        movb 9(%rbp),%al
        test %al,%al
        jne  .next_line

        movl $0,YA_PCOUNT(%rsp)         # reset pair count
        xorl %eax,%eax
        movl %eax, YA_USEDMSK(%rsp)     # clear used-letters mask
        mov  %r9,%rsi                   # rsi = value cursor
.p_lp:
        movb (%rsi),%al
        test %al,%al
        jz   .p_done
        cmpb $' ',%al;  je .p_adv
        cmpb $'\t',%al; je .p_adv
        cmpb $',',%al;  je .p_adv

        # Normalize first letter to uppercase and map to 0..25
        movb (%rsi),%al
        cmpb $'a',%al; jb .p_uA
        cmpb $'z',%al; ja .p_uA
        subb $32,%al
.p_uA:  subb $'A',%al
        cmpb $25,%al;  ja .p_bad

        # Normalize second letter similarly and ensure different from first
        movb 1(%rsi),%dl
        cmpb $'a',%dl; jb .p_uB
        cmpb $'z',%dl; ja .p_uB
        subb $32,%dl
.p_uB:  subb $'A',%dl
        cmpb $25,%dl;  ja .p_bad
        cmpb %al,%dl;  je .p_bad        # pair like 'AA' is invalid

        # Enforce max 10 pairs
        movl YA_PCOUNT(%rsp),%ecx
        cmpl $10,%ecx
        jge  .p_many

        # Dedupe: ensure neither letter already used (via YA_USEDMSK bitmask)
        movl YA_USEDMSK(%rsp),%r8d
        movl $1,%r9d
        movb %al,%cl
        shl  %cl,%r9d
        test %r8d,%r9d; jnz .p_dup
        orl  %r9d,%r8d

        movl $1,%r9d
        movb %dl,%cl
        shl  %cl,%r9d
        test %r8d,%r9d; jnz .p_dup
        orl  %r9d,%r8d
        movl %r8d,YA_USEDMSK(%rsp)

        # Store the pair (a,b) into YA_PAIRS
        movl YA_PCOUNT(%rsp),%ecx
        leaq YA_PAIRS(%rsp),%r10
        movb %al,(%r10,%rcx,2)
        movb %dl,1(%r10,%rcx,2)
        incl %ecx
        movl %ecx,YA_PCOUNT(%rsp)

        add  $2,%rsi                    # consume two letters
        jmp  .p_lp

.p_adv: inc  %rsi                        # skip separator
        jmp  .p_lp

.p_bad:
        movl %r15d,(%r13)
        movl $ERR_PLUG_TOKEN,%eax
        jmp  .fail_close

.p_dup:
        movl %r15d,(%r13)
        movl $ERR_PLUG_DUP,%eax
        jmp  .fail_close

.p_many:
        movl %r15d,(%r13)
        movl $ERR_PLUG_MANY,%eax
        jmp  .fail_close

.p_done:
        jmp  .next_line

# ----------------------------------------------------------------------
# Continue with next line
# ----------------------------------------------------------------------
.next_line:
        jmp .y_read

# ----------------------------------------------------------------------
# End-of-file: verify all required keys were seen
# Required bits:
#   rotors(1) | greek(2) | reflector(4) | rings(8) | positions(16) = 0x1F
# ----------------------------------------------------------------------
.eof:
        movq YA_FLAGS(%rsp),%rax
        andq $0x1F,%rax
        cmpq $0x1F,%rax
        jne  .fail_missing

        jmp   .apply                    # all good -> materialize into *e

.fail_missing:
        movl $0,(%r13)                  # for missing keys, report line 0
        movl $ERR_MISSING,%eax
        jmp  .fail_close                # common error epilogue (close file)


# ==== Apply settings ==========================================================
.apply:
        # === Guard: rotor IDs must be in [1..8] ===============================
        # Rotor indices (L, M, R) parsed from YAML must be within 1..8.
        movzbl YA_ROT(%rsp),   %eax
        cmpb  $1,%al; jb .apply_bad
        cmpb  $8,%al; ja .apply_bad
        movzbl YA_ROT+1(%rsp), %eax
        cmpb  $1,%al; jb .apply_bad
        cmpb  $8,%al; ja .apply_bad
        movzbl YA_ROT+2(%rsp), %eax
        cmpb  $1,%al; jb .apply_bad
        cmpb  $8,%al; ja .apply_bad

        # === Initialize Left rotor (L) ========================================
        # Load wiring string and notch pair, then build W/INV tables.
        movzbl YA_ROT(%rsp),%eax
        leaq rotor_tbl(%rip),%r10
        movq (%r10,%rax,8),%rdx           # RDX = wiring string for rotor L
        leaq E_L(%r12),%rcx               # RCX = &E_L
        movzbl YA_ROT(%rsp),%eax
        decl %eax                         # index into notch table (0-based)
        leaq rotor_notches_tbl(%rip),%r11
        movzbl (%r11,%rax,2),%r8d         # r8d = notch A (ASCII or 0)
        movzbl 1(%r11,%rax,2),%r9d        # r9d = notch B (ASCII or 0)
        call rotor_setup2

        # Apply ring and position for L
        leaq  E_L(%r12),%rcx
        movzbl YA_RING(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_L(%r12),%rcx
        movzbl YA_POS(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Initialize Middle rotor (M) ======================================
        movzbl YA_ROT+1(%rsp),%eax
        leaq rotor_tbl(%rip),%r10
        movq (%r10,%rax,8),%rdx
        leaq E_M(%r12),%rcx
        movzbl YA_ROT+1(%rsp),%eax
        decl %eax
        leaq rotor_notches_tbl(%rip),%r11
        movzbl (%r11,%rax,2),%r8d
        movzbl 1(%r11,%rax,2),%r9d
        call rotor_setup2

        # Apply ring and position for M
        leaq  E_M(%r12),%rcx
        movzbl YA_RING+1(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_M(%r12),%rcx
        movzbl YA_POS+1(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Initialize Right rotor (R) =======================================
        movzbl YA_ROT+2(%rsp),%eax
        leaq rotor_tbl(%rip),%r10
        movq (%r10,%rax,8),%rdx
        leaq E_R(%r12),%rcx
        movzbl YA_ROT+2(%rsp),%eax
        decl %eax
        leaq rotor_notches_tbl(%rip),%r11
        movzbl (%r11,%rax,2),%r8d
        movzbl 1(%r11,%rax,2),%r9d
        call rotor_setup2

        # Apply ring and position for R
        leaq  E_R(%r12),%rcx
        movzbl YA_RING+2(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_R(%r12),%rcx
        movzbl YA_POS+2(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Greek wheel (β/γ) ================================================
        # The Greek wheel does not step; we still set ring/position.
        movzbl YA_GAMMA(%rsp),%eax      # 0 = Beta, 1 = Gamma
        test  %eax,%eax
        jz    .use_beta
        leaq  gamma_str(%rip),%rdx      # wiring = Γ (gamma)
        jmp   .g_have
.use_beta:
        leaq  beta_str(%rip),%rdx       # wiring = β (beta)
.g_have:
        leaq  E_G(%r12),%rcx
        xorl  %r8d,%r8d                 # notchA = 0 (none)
        xorl  %r9d,%r9d                 # notchB = 0 (none)
        call  rotor_setup2

        # Apply ring and position for Greek wheel
        leaq  E_G(%r12),%rcx
        movzbl YA_GRING(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_G(%r12),%rcx
        movzbl YA_GPOS(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Reflector (Thin B / Thin C) ======================================
        # Initialize the 26-byte reflector map from a 13-pair list string.
        # Each constant (rfB_pairs / rfC_pairs) encodes 13 letter pairs
        # concatenated sequentially, e.g. "AE BN CK DQ ..." -> (A–E), (B–N), ...
        # ref_setup_pairs() expands these pairs into a symmetric 26-entry map.
        movzbl YA_REFC(%rsp),%eax
        leaq  E_REF(%r12),%rcx
        test  %eax,%eax
        jz    1f
        # Thin C
        leaq  rfC_pairs(%rip),%rdx       # "AR BD CO EJ FN TG HK IV LM PW QZ SX UY"
        mov   $13,%r8d                   # 13 pairs
        call  ref_setup_pairs
        jmp   2f
1:      # Thin B
        leaq  rfB_pairs(%rip),%rdx       # "AE BN CK DQ FU GY HW IJ LO MP RX SZ TV"
        mov   $13,%r8d                   # 13 pairs
        call  ref_setup_pairs
2:
        # === Plugboard =========================================================
        # Initialize to identity, then apply any parsed letter pairs.
        leaq  E_PB(%r12), %rcx
        call  plug_init

        movl  YA_PCOUNT(%rsp), %r14d       # number of pairs parsed (0..10)
        test  %r14d, %r14d
        jz    .done_ok

        leaq  YA_PAIRS(%rsp), %r10         # base of 2-byte (a,b) pairs
        xorl  %r11d, %r11d                 # current pair index
.pb_loop:
        # Apply one plugboard pair (a, b). (If multiple exist, iterate index.)
        movzbl  (%r10,%r11,2),  %eax       # a = 0..25
        movl    %eax, YA_TMP0(%rsp)
        movzbl  1(%r10,%r11,2), %eax       # b = 0..25
        movl    %eax, YA_TMP1(%rsp)
        leaq    E_PB(%r12), %rcx
        mov     YA_TMP0(%rsp), %edx        # RDX = a
        mov     YA_TMP1(%rsp), %r8d        # R8  = b
        call    plug_pair_idx              # PB[a] <-> PB[b]

.done_ok:
        # Success path: clear *errline, close file, return OK.
        movl  $0,(%r13)
        mov   %rbx,%rcx
        call  fclose
        jmp   .ya_ret_ok

.apply_bad:
        # Rotor ID out of range — set error line and return code.
        movl %r15d,(%r13)
        movl $ERR_ROTOR_NAME,%eax
        jmp  .fail_close


# ==== Common return paths =====================================================
.fail_close:
        # Error path: close file while preserving EAX (error code).
        mov  %eax, %r10d
        mov  %rbx, %rcx
        call fclose
        mov  %r10d, %eax
        jmp  .ya_ret_err

.ya_ret_ok:
        xorl %eax,%eax                   # OK
        jmp  .ya_ret_common

.ya_ret_err:
        # EAX already holds a negative error code.

.ya_ret_common:
        # Epilogue: restore non-volatile registers and return.
        addq $136,%rsp
        pop  %rbp
        pop  %rsi
        pop  %rdi
        pop  %r15
        pop  %r14
        pop  %r13
        pop  %r12
        pop  %rbx
        ret
        .seh_endproc


        .text
        .globl  ref_setup_pairs
        .seh_proc ref_setup_pairs
# ------------------------------------------------------------------------------
# void ref_setup_pairs(uint8* rcx, const uint8* rdx, uint32 count_pairs (r8d))
#
# Purpose:
#   Build a symmetric 26-byte reflector map from a compact list of letter pairs.
#
# Arguments:
#   RCX = destination REF[26]
#   RDX = pointer to 2*count_pairs ASCII letters: (a0,b0,a1,b1,...)
#   R8d = number of pairs (e.g., 13 for Thin B/C)
#
# Behavior:
#   - Initializes REF[i] = i (identity).
#   - For each pair (A,B): REF[A] = B, REF[B] = A.
#   - Ignores out-of-range letters (defensive).
# ------------------------------------------------------------------------------
ref_setup_pairs:
        .seh_endprologue

        # Identity init: REF[i] = i
        xor  %r10d,%r10d
.Linit_loop:
        cmpl $26,%r10d
        jge  .Linit_done
        movb %r10b,(%rcx,%r10,1)
        inc  %r10d
        jmp  .Linit_loop
.Linit_done:

        # Apply symmetric pairs
        xor  %r10d,%r10d
.Lpair_loop:
        cmpl %r8d,%r10d
        jge  .Ldone
        movzbl (%rdx,%r10,2),%eax      # a (ASCII)
        movzbl 1(%rdx,%r10,2),%r9d     # b (ASCII)
        sub    $'A',%eax               # -> 0..25
        sub    $'A',%r9d
        # Skip if either side is out of range
        cmpl $25,%eax
        ja   .Lnext
        cmpl $25,%r9d
        ja   .Lnext
        # Symmetric mapping
        movb %r9b,(%rcx,%rax,1)
        movb %al,(%rcx,%r9,1)
.Lnext:
        inc  %r10d
        jmp  .Lpair_loop

.Ldone:
        ret
        .seh_endproc


# ===== main ===================================================================
        .globl  main
        .seh_proc main
main:
        # --- Prologue: establish frame & alignment -----------------------------
        # Win64 rules:
        #   - Keep RSP 16-byte aligned at call sites.
        #   - First 32 bytes at [rsp+0..31] are the "shadow space" for callees.
        # Here we set up an FP (optional), save a non-volatile (r14),
        # then reserve locals (includes an Enigma state buffer we place at rsp+32).
        push %rbp
        .seh_pushreg %rbp
        mov  %rsp,%rbp
        .seh_setframe %rbp,0
        push %r14
        .seh_pushreg %r14
        # Reserve 360 bytes stack space (keeps 16B alignment + room for locals)
        # Note: callers provide +32B shadow space on Win64; we don't overwrite it.
        subq $360,%rsp
        .seh_stackalloc 360
        .seh_endprologue

        # --- Banner / startup --------------------------------------------------
        leaq fmt_start(%rip),%rcx        # RCX = banner string
        xor  %eax,%eax                   # AL must be 0 for varargs per Win64
        call printf                      # printf("[M4] starting...\n")

        # === Prompt for mode (Encrypt / Decrypt) ===============================
        leaq   fmt_mode(%rip), %rcx      # "[E=encrypt / D=decrypt]: "
        xor    %eax, %eax
        call   printf
.readm:
        call   getchar                   # Read one byte from stdin
        cmp    $-1, %eax                 # EOF?
        je     .mode_default
        cmp    $'\r', %al                # Carriage return?
        je     .mode_default
        cmp    $'\n', %al                # Line feed?
        je     .mode_default

        # Normalize to uppercase; only accept 'E' or 'D'
        cmp    $'a', %al
        jb     .chkED
        cmp    $'z', %al
        ja     .chkED
        sub    $32, %al                  # 'a'..'z' -> 'A'..'Z'
.chkED:
        cmp    $'E', %al
        je     .setE
        cmp    $'D', %al
        je     .setD
        jmp    .readm                    # Any other char -> keep reading

.setE:
        movb   $'E', mode_ch(%rip)       # Persist mode = Encrypt
        jmp    .after_mode
.setD:
        movb   $'D', mode_ch(%rip)       # Persist mode = Decrypt
        jmp    .after_mode
.mode_default:
        movb   $'E', mode_ch(%rip)       # Default to Encrypt if none entered
.after_mode:
        # Drain the rest of the line (tolerate CRLF/LF)
.eatm:
        call   getchar
        cmp    $-1, %eax
        je     .eat_done
        cmp    $'\n', %al
        je     .eat_done
        cmp    $'\r', %al
        jne    .eatm
        # Optional: if CR seen, consume a following LF (Windows CRLF)
        call   getchar
.eat_done:

        # --- Initialize Enigma state buffer -----------------------------------
        # Place the Enigma struct at [rsp+32] (just after shadow space).
        leaq 32(%rsp),%r14               # r14 = &E (Enigma state)
        mov  %r14,%rcx
        mov  $E_SIZE,%rdx                # Zero entire E
        call memzero

# ==== Load YAML configuration (retry until success) ============================
.cfg_try:
        lea   cfg_path(%rip), %rcx       # RCX = "enigma_setting.yml"
        mov   %r14, %rdx                 # RDX = &E (destination)
        lea   err_line(%rip), %r8        # R8  = &err_line
        call  yaml_apply                 # Parse config; EAX = rc (0 ok, <0 err)

        test  %eax, %eax
        jns   .cfg_ok                    # Success (>= 0)

        # On parse failure, print error code + line, then wait for ENTER to retry
        lea   fmt_cfg_err(%rip), %rcx    # "[SETTINGS] parse failed..."
        mov   %eax, %edx                 # EDX = error code
        mov   err_line(%rip), %r8d       # R8d = failing line (0 if open error)
        xor   %eax, %eax
        call  printf

.Lwait_enter_main:
        call  getchar                    # Block until user presses ENTER
        cmp   $'\n', %al
        jne   .Lwait_enter_main
        jmp   .cfg_try                   # Try loading settings again

.cfg_ok:
        # Settings loaded
        leaq   fmt_cfg_ok(%rip), %rcx    # "[SETTINGS] loaded ..."
        xor    %eax, %eax
        call   printf

        # --- Prompt for text depending on mode --------------------------------
        movzbl mode_ch(%rip), %eax
        cmp    $'D', %al
        je     .prompt_D
        leaq   fmt_prompt_E(%rip), %rcx  # "Enter plaintext: "
        xor    %eax, %eax
        call   printf
        jmp    .read_line
.prompt_D:
        leaq   fmt_prompt_D(%rip), %rcx  # "Enter ciphertext: "
        xor    %eax, %eax
        call   printf
        jmp    .read_line

# ==== Read one input line (max 1023 chars; stop at CR/LF/EOF) =================
.read_line:
        leaq  inbuf(%rip), %rdi          # RDI = write ptr
        xor   %ecx, %ecx                 # ECX = count = 0
.read_loop:
        call  getchar
        cmp   $-1, %eax                  # EOF -> finish
        je    .rd_done
        cmp   $'\r', %al                 # CR -> finish
        je    .rd_done
        cmp   $'\n', %al                 # LF -> finish
        je    .rd_done
        cmp   $1023, %ecx                # Cap length at 1023
        jge   .read_loop
        movb  %al, (%rdi)                # Store char
        inc   %rdi
        inc   %ecx
        jmp   .read_loop
.rd_done:
        movb  $0, (%rdi)                 # NUL-terminate input buffer

        # === Encrypt / Decrypt with live HUD ==================================
        leaq  inbuf(%rip),  %rsi         # RSI = input cursor
        leaq  outbuf(%rip), %rdi         # RDI = output cursor

.enc_loop:
        movzbl (%rsi), %edx              # Next input byte -> EDX
        testb  %dl, %dl
        je     .enc_end                  # NUL -> finished

        mov    %r14, %rcx                # RCX = &E
        call   enc_char_m4               # Process char (steps rotors etc.)
        movb   %al, (%rdi)               # Write output byte
        movb   $0, 1(%rdi)               # Temp NUL to printf as a C-string

        # --- HUD: show current rotor windows [L M R] --------------------------
        movzbl E_L+ROTOR_POS(%r14), %eax # Left window (0..25)
        addb   $'A', %al                 # -> ASCII letter
        mov    %eax, %edx
        movzbl E_M+ROTOR_POS(%r14), %eax # Middle window
        addb   $'A', %al
        mov    %eax, %r8d
        movzbl E_R+ROTOR_POS(%r14), %eax # Right window
        addb   $'A', %al
        mov    %eax, %r9d

        # --- HUD header: CT vs PT label per mode ------------------------------
        movzbl mode_ch(%rip), %eax
        cmp    $'D', %al
        je     .hdr_pt
        leaq   fmt_live_hdr_E(%rip), %rcx # "\r[%c %c %c] CT: "
        xor    %eax, %eax
        call   printf
        jmp    .hdr_done
.hdr_pt:
        leaq   fmt_live_hdr_D(%rip), %rcx # "\r[%c %c %c] PT: "
        xor    %eax, %eax
        call   printf

.hdr_done:
        # Print the just-produced character (as a short C-string)
        leaq   fmt_live_ct(%rip), %rcx   # "%s"
        leaq   outbuf(%rip), %rdx
        xor    %eax, %eax
        call   printf

        # Smooth typing feel: flush & sleep a bit
        xor    %rcx, %rcx                # fflush(NULL)
        call   fflush
        mov    $SPEED_MS, %ecx           # delay (ms)
        call   Sleep

        incq   %rsi                      # Advance input ptr
        incq   %rdi                      # Advance output ptr
        jmp    .enc_loop

.enc_end:
        # --- Newline after the live HUD line ----------------------------------
        leaq   fmt_nl(%rip), %rcx
        xor    %eax, %eax
        call   printf

        # === Final summary line ===============================================
        # Example: "[E] PLAINTEXT -> CIPHERTEXT"  or  "[D] CIPHERTEXT -> PLAINTEXT"
        leaq   fmt_result_md(%rip), %rcx
        movzbl mode_ch(%rip), %edx
        leaq   inbuf(%rip),  %r8         # original input
        leaq   outbuf(%rip), %r9         # produced output
        xor    %eax, %eax
        call   printf

        # --- Epilogue: restore non-volatiles and return 0 ---------------------
        addq $360,%rsp
        pop  %r14
        pop  %rbp
        xor  %eax,%eax                   # return code 0
        ret

        .seh_endproc
