        .text
        .globl  main
        .extern printf, fflush, Sleep, getchar, fopen, fgets, fclose

# ==============================================================================
# Enigma M4 (Kriegsmarine) — x86-64, GAS (AT&T syntax), Windows / MinGW-w64
#
# Build (MinGW-w64):
#   x86_64-w64-mingw32-gcc -O2 -s -x assembler .\enigma_m4.asm -o .\enigma_m4.exe
#
# Runtime:
#   - Prompts for mode: Encrypt (E) or Decrypt (D). [default: E]
#   - Prompts for input line (max 1023 bytes; stops at CR/LF; non-letters pass through)
#   - Live HUD:
#       E-mode -> "\r[L M R] CT: <text>"
#       D-mode -> "\r[L M R] PT: <text>"
#     (L/M/R = current window letters; updated every keystroke)
#   - Final summary line:
#       "[E] <PT> -> <CT>"  or  "[D] <CT> -> <PT>"
#
# Config (YAML):
#   - File: "enigma_setting.yml" (UTF-8; line comments '#', doc-start '---' ignored)
#   - Accepts UTF-8 BOM (EF BB BF) only on first line; UTF-16 BOMs are syntax errors.
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
#   - a..z -> A..Z conversion; non-letters pass unchanged.
#   - Greek wheel (β/γ) does not step but affects signal path via ring/position.
#   - Double-stepping implemented (per M notch logic + ring offset correction).
#   - Reflector pairs are guaranteed symmetric (Thin B/C maps).
#   - Plugboard defaults to identity mapping; modified via YAML or plug_pair_idx().
#   - Typing feel delay: SPEED_MS = 180 ms (Win32 Sleep).
# ==============================================================================


# ------------------------------------------------------------------------------
# Tunables
# ------------------------------------------------------------------------------
.set SPEED_MS, 180             # Delay between keypresses in milliseconds
                               # (simulates operator typing rhythm)


# ------------------------------------------------------------------------------
# Rotor structure layout (56 bytes per rotor)
# ------------------------------------------------------------------------------
# [0..25]   ROTOR_W    — forward wiring (A->Z index)
# [26..51]  ROTOR_INV   — inverse wiring
# [52]      ROTOR_NA    — primary notch position (0..25 or 0xFF)
# [53]      ROTOR_NB    — secondary notch position (0..25 or 0xFF)
# [54]      ROTOR_RING  — ring setting (Ringstellung)
# [55]      ROTOR_POS   — current rotor window position
# ------------------------------------------------------------------------------

.set ROTOR_W,    0
.set ROTOR_INV,  26
.set ROTOR_NA,   52
.set ROTOR_NB,   53
.set ROTOR_RING, 54
.set ROTOR_POS,  55
.set ROTOR_SIZE, 56


# ------------------------------------------------------------------------------
# Enigma M4 complete layout (288 bytes total)
# ------------------------------------------------------------------------------
# Offset 0    : Right rotor
# Offset 56   : Middle rotor
# Offset 112  : Left rotor
# Offset 168  : Greek rotor (β/γ; does not step)
# Offset 224  : Reflector table (26 bytes)
# Offset 250  : Plugboard table (26 bytes)
# ------------------------------------------------------------------------------
.set E_R,    0
.set E_M,    56
.set E_L,    112
.set E_G,    168
.set E_REF,  224
.set E_PB,   250
.set E_SIZE, 288


# ------------------------------------------------------------------------------
# BSS — Runtime buffers (allocated zero-initialized)
# ------------------------------------------------------------------------------
        .comm inbuf,  1024, 16        # input buffer (plaintext / ciphertext)
        .comm outbuf, 1024, 16        # output buffer (after encryption)

# YAML parser temporary buffers
        .comm yaml_line, 256, 16      # holds one line read by fgets()
        .comm key_buf,   32,  16      # temporary key name (lower-cased)


# ------------------------------------------------------------------------------
# Data segment — globals and error codes
# ------------------------------------------------------------------------------
        .section .data
mode_ch:        .byte 0        # current mode ('E' or 'D')
err_line:       .long 0        # line number of last YAML error

# YAML parse error codes (negative values -> failure)
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

# --- Reflector pair tables (Thin B / Thin C) -----------------------
# Each pair string represents 13 two-letter swaps (A↔E etc.)
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

# Rotor notches table (2 bytes per rotor -> NA, NB)
# I=Q, II=E, III=V, IV=J, V=Z, VI=Z/M, VII=Z/M, VIII=Z/M
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
# Rotor wiring tables (A=0..Z=25)
# Each string defines forward wiring order; inverse tables are computed at runtime.
# ------------------------------------------------------------------------------
rotI_str:    .ascii "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
rotII_str:   .ascii "AJDKSIRUXBLHWTMCQGZNPYFVOE"
rotIII_str:  .ascii "BDFHJLCPRTXVZNYEIWGAKMUSQO"
rotIV_str:   .ascii "ESOVPZJAYQUIRHXLNFTGKDCMWB"
rotV_str:    .ascii "VZBRGITYUPSDNHLXAWMJQOFECK"
rotVI_str:   .ascii "JPGVOUMFYQBENHZRDKASXLICTW"
rotVII_str:  .ascii "NZJHGRCXMYSWBOUFAIVLPEKQDT"
rotVIII_str: .ascii "FKQHTLXOCBJSPDZRAMEWNIUYGV"

# Greek rotors used only in Kriegsmarine M4 machines
beta_str:    .ascii "LEYJVCNIXWPBQMDRTAKZGFUHOS"
gamma_str:   .ascii "FSOKANUERHMBTIYCWLQPZXVGJD"


# ===== Utility: memset-like zero ==============================================
        .text
        .globl  memzero
        .seh_proc memzero
memzero:
        .seh_endprologue              # Win64 SEH: no prologue state to unwind

        # Args (Win64 SysV-like via MS x64):
        #   rcx = dst pointer
        #   rdx = length in bytes (size_t)
        # Clobbers: rax
        # Effect  : memset(dst, 0, len)

        test %rdx,%rdx                # if len == 0 -> return
        jz   .mz_ret
        xor  %rax,%rax                # rax = 0 (byte source)

.mz_loop:
        movb %al,(%rcx)               # *dst = 0
        inc  %rcx                     # dst++
        dec  %rdx                     # len--
        jnz  .mz_loop                 # continue while len != 0

.mz_ret:
        ret
        .seh_endproc


# ===== rotor_setup2 ===========================================================
# void rotor_setup2(Rotor* rcx, const char* map, uint8 notchA(r8b), uint8 notchB(r9b))
# - From ASCII map "A..Z", builds:
#     W   (forward wiring) at ROTOR_W
#     INV (inverse wiring) at ROTOR_INV
# - Stores notches:
#     NA = notchA ? notchA - 'A' : 0xFF
#     NB = notchB ? notchB - 'A' : 0xFF
# Assumes:
#   - 'map' length ≥ 26 and only 'A'..'Z'
#   - Rotor struct layout per ROTOR_* constants
        .globl  rotor_setup2
        .seh_proc rotor_setup2
rotor_setup2:
        .seh_endprologue

        # rdx = map ("EKMFLG..."), r8b = notchA (ASCII or 0), r9b = notchB (ASCII or 0)
        # rcx = Rotor* (destination)
        # r10d used as i (0..25), rax as temp

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
# - Builds a 26-byte symmetric reflector table REF where:
#     Initially: REF[i] = i (identity)
#     For i in 0..25: let a = rdx[i] - 'A'; set REF[i] = a; REF[a] = i
#   The input 'rdx' is a 26-char "pair string" (13 pairs) such that
#   every index appears exactly once across pairs (Thin B/C encoded).
# Notes:
#   - Assumes pairs are consistent and cover all letters exactly once.
#   - Caller typically passes rfB_pairs or rfC_pairs.
        .globl  ref_setup_sym
        .seh_proc ref_setup_sym
ref_setup_sym:
        .seh_endprologue

        # rcx = REF base (uint8[26])
        # rdx = ASCII pair string (26 chars)
        # r10d used as i, rax as temp

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
# Apply symmetric pairs from the string
.rs3:
        cmpl $26,%r10d
        jge  .rs4

        movzbl (%rdx,%r10,1),%eax     # a = pairs[i] (ASCII)
        subb  $'A',%al                # a = a - 'A' (0..25)

        movb  %al,(%rcx,%r10,1)       # REF[i]   = a
        movb  %r10b,(%rcx,%rax,1)     # REF[a]   = i  (ensure symmetry)

        incl  %r10d
        jmp   .rs3

.rs4:
        ret
        .seh_endproc


# ===== Plugboard ==============================================================
# Plugboard = 26-byte substitution map (A–Z)
# Default: identity (PB[i] = i)
# Can be modified with pair swaps (e.g., AB, CD ⇒ PB[0]=1, PB[1]=0, PB[2]=3, PB[3]=2, …)

        .globl  plug_init
        .seh_proc plug_init
# void plug_init(uint8* rcx)
# - Initializes plugboard to identity mapping PB[i] = i
#   rcx = pointer to plugboard table (26 bytes)
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
# - Swaps two entries PB[a] and PB[b] by index (0..25)
#   Used to implement plugboard letter pairs (e.g., A↔B).
#   Win64 ABI: rcx=PB, rdx=a, r8=b
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
# - Returns 1 if the current rotor is at a turnover notch position.
#   The check uses (pos - ring) mod 26, compared to NA/NB.
#   Used in double-stepping logic: triggers neighbor stepping.
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
# Forward path: right → left through forward wiring table W.
#
# Formula:
#   y = W[(x + POS - RING) mod 26] - POS + RING
#
# Registers:
#   rcx = Rotor*
#   edx = input letter index (0..25)
# Returns:
#   eax = output letter index (0..25)
#
# Optimizations:
#   - Reads POS/RING once per call
#   - All modulo-26 wraps done branchlessly (via CMOV)
#   - No unpredictable branches → stable timing
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
        lea    %eax, (%rdx,%r8d)          # eax = x + POS
        subl   %r9d, %eax                 # eax = x + POS - RING
        # Range of t ≈ [-25 .. 50]

        # --- Wrap input index to [0, 25] without branches -------------
        # If t >= 26 → subtract 26
        lea    %r10d, -26(%rax)           # r10d = t - 26
        cmpl   $26, %eax
        cmovge %r10d, %eax                # eax = (t >= 26) ? t - 26 : t
        # If t < 0 → add 26
        lea    %r10d, 26(%rax)            # r10d = t + 26
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
        lea    %r10d, -26(%rax)           # r10d = y - 26
        cmpl   $26, %eax
        cmovge %r10d, %eax                # if y >= 26 → y -= 26
        lea    %r10d, 26(%rax)            # r10d = y + 26
        testl  %eax, %eax
        cmovl  %r10d, %eax                # if y < 0  → y += 26

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
        # Backward path: left -> right through inverse wiring table.
        # Formula:
        #   y = INV[(x + POS - RING) mod 26] - POS + RING
        #
        # Registers:
        #   rcx = Rotor*
        #   edx = input letter index (0..25)
        # Returns:
        #   eax = output letter index (0..25)
        #
        # Optimizations:
        #   - Reads POS/RING once
        #   - Wrap (mod 26) handled branchlessly via CMOV
        #   - Keeps result always in range [0..25]
        # ============================================================

        # --- Load rotor offsets ------------------------------------
        movzbl ROTOR_POS(%rcx), %r8d       # r8d = rotor->POS
        movzbl ROTOR_RING(%rcx), %r9d      # r9d = rotor->RING

        # --- Compute (x + POS - RING) -------------------------------
        lea    %eax, (%rdx,%r8d)           # eax = x + POS
        subl   %r9d, %eax                  # eax = x + POS - RING
        # Range of eax ≈ [-25 .. 50]

        # --- Wrap into [0,26) without branches ----------------------
        lea    %r10d, -26(%rax)            # r10d = eax - 26
        cmpl   $26, %eax                   # if eax >= 26
        cmovge %r10d, %eax                 #   eax -= 26
        lea    %r10d, 26(%rax)             # r10d = eax + 26
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
        lea    %r10d, -26(%rax)            # r10d = eax - 26
        cmpl   $26, %eax
        cmovge %r10d, %eax                 # if eax >= 26 -> subtract 26
        lea    %r10d, 26(%rax)             # r10d = eax + 26
        testl  %eax, %eax
        cmovl  %r10d, %eax                 # if eax < 0  -> add 26

        # --- Return result in eax (0..25) ---------------------------
        ret
        .seh_endproc

# ===== step_m4 ================================================================
# void step_m4(Enigma* rcx)
# - Steps only the three moving rotors R/M/L (Greek rotor does not step).
# - Implements historical double-stepping:
#     * If Middle (M) is at notch -> step M and Left (L).
#     * If Right  (R) is at notch -> step M.
#   Note: rotor_at_notch() compares (POS - RING) mod 26 to NA/NB.
# - Win64 ABI: rcx = Enigma* base
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

        # If M at notch: step L only (double-step trigger)
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

        # Step M once if (mflag | rflag)
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

        # Always step R
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
# Pipeline:
#   1) Uppercase; non-letters pass through unchanged.
#   2) Step rotors: step_m4(enigma).
#   3) PB in:       x = PB[ch - 'A'].
#   4) Forward:     x = R->M->L->G (Greek rotor is fixed position, but still maps).
#   5) Reflect:     x = REF[x].
#   6) Backward:    x = G->L->M->R (inverse paths).
#   7) PB out:      x = PB[x]; return x + 'A'.
# Registers (Win64):
#   rcx = Enigma* ; edx = input ASCII; returns al (ASCII)
# Clobbers: r12, r13, r15 (saved)
        .globl  enc_char_m4
        .seh_proc enc_char_m4
enc_char_m4:
        push %r12
        .seh_pushreg %r12
        push %r13
        .seh_pushreg %r13
        push %r15
        .seh_pushreg %r15
        subq $32,%rsp                    # 32B shadow space
        .seh_stackalloc 32
        .seh_endprologue

        movq  %rcx,%r12                  # r12 = enigma*
        movl  %edx,%r15d                 # preserve original ASCII input

        # --- Uppercase; if not alphabetic, return as-is ----------------------
        movl  %edx,%eax                  # al = ch
        cmpb  $'a',%al
        jb    .uc_ok
        cmpb  $'z',%al
        ja    .uc_ok
        subb  $32,%al                    # 'a'..'z' -> 'A'..'Z'
.uc_ok:
        cmpb  $'A',%al
        jb    .nonalpha
        cmpb  $'Z',%al
        ja    .nonalpha
        movzbl %al,%r13d                 # r13d = ch ('A'..'Z')

        # --- Step rotors (R/M/L with double-step semantics) ------------------
        movq  %r12,%rcx
        call  step_m4

        # --- Plugboard in ----------------------------------------------------
        movl  %r13d,%edx
        subl  $'A',%edx                  # to 0..25
        movzbl E_PB(%r12,%rdx,1),%edx    # edx = PB_in[x]

        # --- Forward path: R -> M -> L -> Greek --------------------------------
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

        # --- Reflector (Thin B/C) --------------------------------------------
        movzbl E_REF(%r12,%rax,1),%eax   # eax = REF[eax]

        # --- Backward path: Greek -> L -> M -> R --------------------------------
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
        call  rotor_bwd                  # eax = 0..25

        # --- Plugboard out and return ASCII ----------------------------------
        movzbl E_PB(%r12,%rax,1),%eax    # eax = PB_out[eax]
        addb  $'A',%al                   # to ASCII 'A'..'Z'

        addq  $32,%rsp
        pop   %r15
        pop   %r13
        pop   %r12
        ret

.nonalpha:
        # Non-letter: return original input byte unchanged
        movb  %r15b,%al
        addq  $32,%rsp
        pop   %r15
        pop   %r13
        pop   %r12
        ret
        .seh_endproc


# ==== locals layout (LEAVE 32B SHADOW SPACE UNUSED) ===========================
# Stack frame note:
#   - Keep the first 32 bytes at [rsp+0..31] reserved for Win64 "shadow space".
#   - All local temporaries start after YA_BASE (= 32).
#
# Local variables (relative to current RSP after prologue stackalloc):
#   YA_FLAGS : bit flags indicating which YAML keys were seen (have_*).
#   YA_ROT   : 3 bytes (L,M,R) rotor IDs (1..8) packed in 64-bit slot.
#   YA_RING  : 3 bytes ring settings (0..25), order (L,M,R).
#   YA_POS   : 3 bytes positions (0..25), order (L,M,R).
#   YA_GAMMA : greek_is_gamma (1 if γ, 0 if β).
#   YA_REFC  : reflector_is_C (1 if Thin C, 0 if Thin B).
#   YA_GRING : Greek ring (0..25).
#   YA_GPOS  : Greek position (0..25).
#   YA_PCOUNT: number of plugboard pairs parsed (0..10).
#   YA_PAIRS : up to 10 pairs × 2 bytes -> 20 bytes used (we allocate 32B aligned).
#   YA_USEDMSK: bitmask of letters already used in plugboard (dedupe check).
#   YA_TMP0  : temp token (32-bit), often holds parsed values.
#   YA_TMP1  : temp counter (32-bit), e.g., token count per line.
#
        .set YA_BASE,     32            # shadow space 32B (kept unused by us)
        .set YA_FLAGS,    YA_BASE+0     # have_* bit
        .set YA_ROT,      YA_BASE+8     # rotorLMR[3] (L,M,R)
        .set YA_RING,     YA_BASE+16    # rings[3]
        .set YA_POS,      YA_BASE+24    # positions[3]
        .set YA_GAMMA,    YA_BASE+32    # greek_is_gamma (byte)
        .set YA_REFC,     YA_BASE+33    # reflector_is_C  (byte)
        .set YA_GRING,    YA_BASE+34    # greek_ring      (byte)
        .set YA_GPOS,     YA_BASE+35    # greek_pos       (byte)
        .set YA_PCOUNT,   YA_BASE+40    # plug_count (int)
        .set YA_PAIRS,    YA_BASE+48    # plug_pairs[20] (10*2 bytes)
        .set YA_USEDMSK,  YA_BASE+80    # used bitmask (int)
        .set YA_TMP0,     YA_BASE+84    # token(32-bit)
        .set YA_TMP1,     YA_BASE+88    # count(32-bit)

# ------------------------------------------------------------------------------
# int yaml_apply(const char* path, void* e, int* errline)
#   RCX=path, RDX=e*, R8=&errline(int).  EAX=0 on success, <0 on error code.
# Purpose:
#   - Open YAML config file (binary mode "rb").
#   - Parse line-by-line into local staging area (these YA_* locals).
#   - Validate/normalize values (BOM, keys, tokens, ranges).
#   - On error: set *errline to failing line and return negative code.
#   - On success: write parsed settings into Enigma* e.
# Notes:
#   - Keeps detailed local state (flags, masks) to detect duplicates, counts, etc.
#   - This prologue saves all necessary callee-saved regs since we call libc.
# ------------------------------------------------------------------------------
        .globl  yaml_apply
        .seh_proc yaml_apply
yaml_apply:
        # ========== Save callee-saved registers per Win64 ==========
        push %rbx                        # FILE* and scratch
        .seh_pushreg %rbx
        push %r12                        # e* (Enigma*)
        .seh_pushreg %r12
        push %r13                        # &errline
        .seh_pushreg %r13
        push %r14                        # path
        .seh_pushreg %r14
        push %r15                        # line number / counters
        .seh_pushreg %r15
        push %rdi                        # scratch callee-saved
        .seh_pushreg %rdi
        push %rsi                        # scratch callee-saved
        .seh_pushreg %rsi
        push %rbp                        # frame base if needed
        .seh_pushreg %rbp

        # Allocate stack space for locals:
        #  - 136 bytes = 32B shadow (we won't touch) + our YA_* locals area.
        subq $136,%rsp
        .seh_stackalloc 136
        .seh_endprologue

        # --------- Move arguments into preserved registers ----------
        mov  %rcx, %r14                 # r14 = path
        mov  %rdx, %r12                 # r12 = e*
        mov  %r8,  %r13                 # r13 = &errline

        # --------- Open file: fopen(path, "rb") ---------------------
        leaq rb_mode(%rip), %rdx        # rdx = "rb"
        mov  %r14, %rcx                 # rcx = path
        call fopen
        test %rax, %rax
        jnz  .fp_ok                     # if (FILE*) != NULL -> ok

        # fopen failed: report line = 0 and return ERR_OPEN
        movl $0,(%r13)                  # *errline = 0
        movl $ERR_OPEN,%eax             # eax = -1
        jmp  .ya_ret_err

.fp_ok:
        mov  %rax, %rbx                 # rbx = FILE*

        # ==== Initialize locals (do NOT touch [rsp+0..31]) =========
        # Zero all our local slots; this also implicitly clears small byte fields.
        xor  %rax,%rax
        movq %rax, YA_FLAGS(%rsp)       # have_* flags = 0
        movq %rax, YA_ROT(%rsp)         # rotor LMR = 0
        movq %rax, YA_RING(%rsp)        # rings LMR = 0
        movq %rax, YA_POS(%rsp)         # positions LMR = 0
        movq %rax, YA_GAMMA(%rsp)       # greek_is_gamma.. etc. cleared
        movq %rax, YA_PCOUNT(%rsp)      # plug_count = 0
        movq %rax, YA_PAIRS(%rsp)       # clear pairs[0..7]
        movq %rax, YA_PAIRS+8(%rsp)
        movq %rax, YA_PAIRS+16(%rsp)
        movq %rax, YA_USEDMSK(%rsp)     # used bitmask = 0

        xorl %r15d,%r15d                # lineno = 0

        # From here:
        #  - Typical flow is: fgets(yaml_line) -> strip BOM/comments -> parse key
        #  - Accumulate tokens into YA_*; increment YA_PCOUNT for plugboard pairs
        #  - On any error: set *errline=lineno and jump to error return
        #  - On EOF with all required fields present: materialize into *e
        #


# ==== line loop ===============================================================
# Reads one line at a time, strips comments/whitespace, handles BOM/doc-start,
# splits into key:value, normalizes key to lowercase into key_buf, and advances
# r9 to the start of the value (with leading spaces/tabs skipped).
.y_read:
        # fgets(yaml_line, 256, fp)
        leaq yaml_line(%rip),%rcx       # rcx = &yaml_line[0]
        mov  $256,%edx                  # edx = size
        mov  %rbx,%r8                   # r8  = FILE* fp
        call fgets
        test %rax,%rax                  # NULL on EOF / error
        jnz  .got_line
        jmp  .eof

.got_line:
        incl %r15d                      # ++lineno

        # --- strip end-of-line comments: find first '#' and terminate there ---
        leaq yaml_line(%rip),%rdi       # rdi = p = line start
.cmt_scan:
        movb (%rdi),%al                 # read char
        test %al,%al                    # NUL? (end of string)
        jz   .after_cmt
        cmpb $'#',%al                   # comment start?
        je   .cut_here
        inc  %rdi
        jmp  .cmt_scan

.cut_here:
        movb $0,(%rdi)                  # terminate string at '#'

.after_cmt:

        # --- trim trailing spaces: walk to end, then back over WS/CR/LF ------
        leaq yaml_line(%rip),%rdi       # rdi = start
        mov  %rdi,%rsi                  # rsi = scan = start

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
        jne  .after_trim                # not WS/CR/LF -> stop
.z0:
        movb $0,(%rsi)                  # trim it
        cmp  %rsi,%rdi
        je   .after_trim                # all trimmed -> done
        dec  %rsi
        jmp  .bt1

.after_trim:
        # --- skip leading spaces/tabs ----------------------------------------
        leaq yaml_line(%rip),%rsi       # rsi = start of (possibly trimmed) line
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
        # --- reject UTF-16 BOMs (FE FF or FF FE) at buffer head --------------
        cmpb $0xFF, (%rsi)              # check 0xFF 0xFE (UTF-16 LE BOM)
        jne  1f
        cmpb $0xFE, 1(%rsi)
        jne  1f
        movl %r15d,(%r13)               # *errline = lineno
        movl $ERR_SYNTAX,%eax
        jmp  .fail_close
1:
        cmpb $0xFE, (%rsi)              # check 0xFE 0xFF (UTF-16 BE BOM)
        jne  .no_bom
        cmpb $0xFF, 1(%rsi)
        jne  .no_bom
        movl %r15d,(%r13)
        movl $ERR_SYNTAX,%eax
        jmp  .fail_close

        # --- accept UTF-8 BOM (EF BB BF) only at very beginning --------------
        cmpb $0xEF,(%rsi)
        jne  .no_bom
        cmpb $0xBB,1(%rsi)
        jne  .no_bom
        cmpb $0xBF,2(%rsi)
        jne  .no_bom
        add  $3,%rsi                    # skip BOM
.no_bom:

        # --- skip YAML doc-start line '---' ----------------------------------
        cmpb $'-',(%rsi)
        jne  .after_bof
        cmpb $'-',1(%rsi)
        jne  .after_bof
        cmpb $'-',2(%rsi)
        jne  .after_bof
        jmp  .next_line                 # skip the '---' line entirely

.after_bof:
        movb  (%rsi), %al               # empty after trims?
        test  %al, %al
        jz    .next_line                # blank line -> read next

        # --- find the colon that separates key and value ---------------------
        mov   %rsi, %rdi                # rdi = scan from current position
        jmp   .findc

.findc:
        movb (%rdi),%al
        test %al,%al
        jz   .next_line                 # no ':' found -> empty/invalid -> skip
        cmpb $':',%al
        je   .gotc                      # ASCII colon found

        # --- also treat full-width colon U+FF1A (EF BC 9A) as ':' ------------
        cmpb $0xEF,%al
        jne  .fc_next
        cmpb $0xBC,1(%rdi)
        jne  .fc_next
        cmpb $0x9A,2(%rdi)
        jne  .fc_next
        add  $3,%rdi                    # consume U+FF1A triple
        jmp  .gotc

.fc_next:
        inc  %rdi
        jmp  .findc


.gotc:
        # key := slice [rsi .. rdi-1], lowercased into key_buf
        leaq key_buf(%rip),%rcx         # rcx = dest (key_buf)
        mov  %rcx,%r8                   # r8  = dest cursor
        mov  %rsi,%r9                   # r9  = src cursor (line start for key)

.kcp:
        cmp  %r9,%rdi                   # while (src < colon)
        je   .kdone
        movb (%r9),%al
        cmpb $'A',%al                   # 'A'..'Z' -> to lowercase
        jb   .kp
        cmpb $'Z',%al
        ja   .kp
        addb $32,%al                    # ASCII: +32 -> lowercase

.kp:
        movb %al,(%r8)                  # store to key_buf
        inc  %r8
        inc  %r9
        jmp  .kcp

.kdone:
        movb $0,(%r8)                   # NUL-terminate key_buf

        # v = colon+1; then skip leading spaces/tabs in value
        lea  1(%rdi),%r9                # r9 points just after ':' (or U+FF1A)

.vskip:
        movb (%r9),%al
        cmpb $' ',%al
        je   .vs1
        cmpb $'\t',%al
        jne  .vready                    # first non-space/tab -> value starts
.vs1:
        inc  %r9
        jmp  .vskip


.vready:
        # ==== key branch ======================================================
        leaq key_buf(%rip),%rcx         # rcx = key_buf (lowercased key text)

        # ----------------------------------------------------------------------
        # key == "rotors"
        #   - Expected value: three Roman numerals for (L M R), e.g. "I II III"
        #   - Accepts separators: space, tab, comma
        #   - Roman parser below supports: I, II, III, IV, V, VI, VII, VIII
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

        # --- parse rotors: 3 Roman tokens in order (L M R) --------------------
        mov  %r9,%rdi                    # rdi = p = start of value text
        xorl %eax,%eax
        movb %al, YA_ROT(%rsp)           # clear L slot
        movb %al, YA_ROT+1(%rsp)         # clear M slot
        movb %al, YA_ROT+2(%rsp)         # clear R slot
        movl $0,%edx                     # edx = count of parsed tokens

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
        # Normalize leading letter to uppercase (allow lowercases in input)
        movb (%rdi),%al
        cmpb $'a',%al; jb .r0
        cmpb $'z',%al; ja .r0
        subb $32,%al                     # 'a'..'z' -> 'A'..'Z'

.r0:
        # Dispatch first Roman letter: 'I' or 'V'
        cmpb $'I',%al; je .tok_I
        cmpb $'V',%al; je .tok_V
        jmp  .rot_bad                    # anything else -> error

# ----------------------------- Roman: starts with I ---------------------------
# Supports: I, II, III, IV
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
# Supports: V, VI, VII, VIII
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
# On entry: eax = parsed value (1..8), rdi advanced past token.
# Caller is expected to store into YA_ROT[L/M/R] based on 'count' and continue.

.tok_ok:
        movl %eax, YA_TMP0(%rsp)      # token
        movl %edx, YA_TMP1(%rsp)      # count

        cmpl $0,%edx; je .savL
        cmpl $1,%edx; je .savM
        cmpl $2,%edx; je .savR
        jmp  .rt_end


.savL:
        movb %al, YA_ROT(%rsp)
        incl %edx
        movl %edx, YA_TMP1(%rsp)

        jmp  .rtok_lp

.savM:
        movb %al, YA_ROT+1(%rsp)
        incl %edx
        movl %edx, YA_TMP1(%rsp)

        jmp  .rtok_lp

.savR:
        movb %al, YA_ROT+2(%rsp)
        incl %edx
        movl %edx, YA_TMP1(%rsp)

        jmp  .rtok_lp


.rot_bad:
        movl %r15d,(%r13)
        movl $ERR_ROTOR_NAME,%eax
        jmp  .fail_close
        
.rt_end:
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
        orq  $1,%rax
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line


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
        subb $32,%al
.g_upd:
        cmpb $'G',%al; je .is_gamma
        cmpb $'B',%al; je .is_beta
        movl %r15d,(%r13)
        movl $ERR_GREEK,%eax
        jmp  .fail_close
.is_gamma:
        movb $1,YA_GAMMA(%rsp)
        jmp  .g_ok
.is_beta:
        movb $0,YA_GAMMA(%rsp)
.g_ok:
        movq YA_FLAGS(%rsp),%rax
        orq  $2,%rax
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line

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
        movb $0,YA_REFC(%rsp)
        mov  %r9,%rsi
.rf_s:  movb (%rsi),%al
        test %al,%al
        jz   .rf_done
        cmpb $'c',%al; je .rf_c
        cmpb $'C',%al; je .rf_c
        inc  %rsi
        jmp  .rf_s
.rf_c:  movb $1,YA_REFC(%rsp)
.rf_done:
        movq YA_FLAGS(%rsp),%rax
        orq  $4,%rax
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line

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
        xorl %ecx,%ecx
.rg_lp:
        movb (%rsi),%al
        test %al,%al
        jz   .rg_done
        cmpb $'A',%al; jb .rg_adv
        cmpb $'Z',%al; jbe .rg_cap
        cmpb $'a',%al; jb .rg_adv
        cmpb $'z',%al; ja .rg_adv
        subb $32,%al
.rg_cap:
        subb $'A',%al
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
        jne  .rings_err
        movq YA_FLAGS(%rsp),%rax
        orq  $8,%rax
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line
.rings_err:
        movl %r15d,(%r13)
        movl $ERR_RINGS,%eax
        jmp  .fail_close

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
        subb $32,%al
.gr_ok:
        subb $'A',%al
        cmpb $25,%al; ja .gr_err
        movb %al,YA_GRING(%rsp)
        jmp  .next_line
.gr_err:
        movl %r15d,(%r13)
        movl $ERR_GREEK_RING,%eax
        jmp  .fail_close

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
        xorl %ecx,%ecx
.ps_lp:
        movb (%rsi),%al
        test %al,%al
        jz   .ps_done
        cmpb $'A',%al; jb .ps_adv
        cmpb $'Z',%al; jbe .ps_cap
        cmpb $'a',%al; jb .ps_adv
        cmpb $'z',%al; ja .ps_adv
        subb $32,%al
.ps_cap:
        subb $'A',%al
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
        orq  $16,%rax
        movq %rax,YA_FLAGS(%rsp)
        jmp  .next_line
.pos_err:
        movl %r15d,(%r13)
        movl $ERR_POSITIONS,%eax
        jmp  .fail_close

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
        subb $32,%al
.gp_ok:
        subb $'A',%al
        cmpb $25,%al; ja .gp_err
        movb %al,YA_GPOS(%rsp)
        jmp  .next_line
.gp_err:
        movl %r15d,(%r13)
        movl $ERR_GREEK_POS,%eax
        jmp  .fail_close

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

        movl $0,YA_PCOUNT(%rsp)
        xorl %eax,%eax
        movl %eax, YA_USEDMSK(%rsp)
        mov  %r9,%rsi
.p_lp:
        movb (%rsi),%al
        test %al,%al
        jz   .p_done
        cmpb $' ',%al;  je .p_adv
        cmpb $'\t',%al; je .p_adv
        cmpb $',',%al;  je .p_adv
        movb (%rsi),%al
        cmpb $'a',%al; jb .p_uA
        cmpb $'z',%al; ja .p_uA
        subb $32,%al
.p_uA:  subb $'A',%al
        cmpb $25,%al;  ja .p_bad
        movb 1(%rsi),%dl
        cmpb $'a',%dl; jb .p_uB
        cmpb $'z',%dl; ja .p_uB
        subb $32,%dl
.p_uB:  subb $'A',%dl
        cmpb $25,%dl;  ja .p_bad
        cmpb %al,%dl;  je .p_bad

        movl YA_PCOUNT(%rsp),%ecx
        cmpl $10,%ecx
        jge  .p_many

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

        movl YA_PCOUNT(%rsp),%ecx
        leaq YA_PAIRS(%rsp),%r10
        movb %al,(%r10,%rcx,2)
        movb %dl,1(%r10,%rcx,2)
        incl %ecx
        movl %ecx,YA_PCOUNT(%rsp)
        add  $2,%rsi
        jmp  .p_lp
.p_adv: inc  %rsi
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

.next_line:
        jmp .y_read

.eof:
        # required keys check...
        movq YA_FLAGS(%rsp),%rax
        andq $0x1F,%rax
        cmpq $0x1F,%rax
        jne  .fail_missing

        jmp   .apply

.fail_missing:
        movl $0,(%r13)
        movl $ERR_MISSING,%eax
        jmp  .fail_close

# ==== Apply settings ==========================================================
.apply:
        # === Defensive guard: rotors ∈ [1..8] ===
        # Verify that rotor indices (L, M, R) parsed from YAML are within valid range [1..8].
        movzbl YA_ROT(%rsp),   %eax
        cmpb  $1,%al; jb .apply_bad
        cmpb  $8,%al; ja .apply_bad
        movzbl YA_ROT+1(%rsp), %eax
        cmpb  $1,%al; jb .apply_bad
        cmpb  $8,%al; ja .apply_bad
        movzbl YA_ROT+2(%rsp), %eax
        cmpb  $1,%al; jb .apply_bad
        cmpb  $8,%al; ja .apply_bad

        # === Left rotor (L) initialization ===
        # Lookup wiring & notch table entries and initialize left rotor (E_L).
        movzbl YA_ROT(%rsp),%eax
        leaq rotor_tbl(%rip),%r10
        movq (%r10,%rax,8),%rdx           # RDX = wiring string
        leaq E_L(%r12),%rcx               # RCX = &E_L
        movzbl YA_ROT(%rsp),%eax
        decl %eax
        leaq rotor_notches_tbl(%rip),%r11
        movzbl (%r11,%rax,2),%r8d          # notch A
        movzbl 1(%r11,%rax,2),%r9d         # notch B
        call rotor_setup2
        # Reload RCX (clobbered by call)
        leaq  E_L(%r12),%rcx
        movzbl YA_RING(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)         # set ring offset
        leaq  E_L(%r12),%rcx
        movzbl YA_POS(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)          # set rotor position

        # === Middle rotor (M) initialization ===
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
        # Reload RCX
        leaq  E_M(%r12),%rcx
        movzbl YA_RING+1(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_M(%r12),%rcx
        movzbl YA_POS+1(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Right rotor (R) initialization ===
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
        # Reload RCX
        leaq  E_R(%r12),%rcx
        movzbl YA_RING+2(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_R(%r12),%rcx
        movzbl YA_POS+2(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Greek wheel (β/γ) setup ===
        # The Greek wheel (Beta or Gamma) does not step; notch = none.
        movzbl YA_GAMMA(%rsp),%eax      # 0 = beta, 1 = gamma
        test  %eax,%eax
        jz    .use_beta
        leaq  gamma_str(%rip),%rdx      # use gamma wiring
        jmp   .g_have
.use_beta:
        leaq  beta_str(%rip),%rdx       # use beta wiring
.g_have:
        leaq  E_G(%r12),%rcx
        xorl  %r8d,%r8d                 # no notch
        xorl  %r9d,%r9d
        call  rotor_setup2
        # Reload RCX and apply ring/position settings
        leaq  E_G(%r12),%rcx
        movzbl YA_GRING(%rsp),%eax
        movb  %al,ROTOR_RING(%rcx)
        leaq  E_G(%r12),%rcx
        movzbl YA_GPOS(%rsp),%eax
        movb  %al,ROTOR_POS(%rcx)

        # === Reflector (Thin B/C) ===
        # Select and initialize thin reflector (B or C) with pre-defined pairs.
        movzbl YA_REFC(%rsp),%eax
        leaq  E_REF(%r12),%rcx
        test  %eax,%eax
        jz    1f
        # Thin C
        leaq  rfC_pairs(%rip),%rdx
        mov   $13,%r8d
        call  ref_setup_pairs
        jmp   2f
1:      # Thin B
        leaq  rfB_pairs(%rip),%rdx
        mov   $13,%r8d
        call  ref_setup_pairs
2:
        # === Plugboard initialization ===
        leaq  E_PB(%r12), %rcx
        call  plug_init

        movl  YA_PCOUNT(%rsp), %r14d       # number of plugboard pairs
        test  %r14d, %r14d
        jz    .done_ok

        leaq  YA_PAIRS(%rsp), %r10         # base of 2-byte plug pairs
        xorl  %r11d, %r11d                 # index = 0

.pb_loop:
        # Apply plugboard pair (a, b)
        movzbl  (%r10,%r11,2),  %eax       # a = 0..25
        movl    %eax, YA_TMP0(%rsp)
        movzbl  1(%r10,%r11,2), %eax       # b = 0..25
        movl    %eax, YA_TMP1(%rsp)
        leaq    E_PB(%r12), %rcx
        mov     YA_TMP0(%rsp), %edx        # RDX = a
        mov     YA_TMP1(%rsp), %r8d        # R8  = b
        call    plug_pair_idx              # swap PB[a] and PB[b]

.done_ok:
        # Success: clear *errline, close FILE*, and return OK
        movl  $0,(%r13)
        mov   %rbx,%rcx
        call  fclose
        jmp   .ya_ret_ok

.apply_bad:
        # Invalid rotor index detected — set error line and return code
        movl %r15d,(%r13)
        movl $ERR_ROTOR_NAME,%eax
        jmp  .fail_close



.fail_close:
        # Common error handler: close FILE*, preserve error code in EAX
        mov  %eax, %r10d
        mov  %rbx, %rcx
        call fclose
        mov  %r10d, %eax
        jmp  .ya_ret_err

.ya_ret_ok:
        # Normal return: EAX = 0 (success)
        xorl %eax,%eax
        jmp  .ya_ret_common

.ya_ret_err:
        # Error return: EAX already holds negative error code

.ya_ret_common:
        # Common epilogue — restore registers and return
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
# void ref_setup_pairs(uint8* rcx, const uint8* rdx, uint32 count_pairs (r8d))
# RCX = destination reflector array (26 bytes)
# RDX = pointer to ASCII pair list (2 * count bytes)
# R8d = number of pairs
# Initializes REF[i] = i, then applies symmetric letter swaps from pair list.
ref_setup_pairs:
        .seh_endprologue
        # Initialize REF[i] = i (identity mapping)
        xor  %r10d,%r10d
.Linit_loop:
        cmpl $26,%r10d
        jge  .Linit_done
        movb %r10b,(%rcx,%r10,1)
        inc  %r10d
        jmp  .Linit_loop
.Linit_done:
        # Apply all provided pairs
        xor  %r10d,%r10d
.Lpair_loop:
        cmpl %r8d,%r10d
        jge  .Ldone
        movzbl (%rdx,%r10,2),%eax      # a (ASCII)
        movzbl 1(%rdx,%r10,2),%r9d     # b (ASCII)
        sub    $'A',%eax               # convert to 0..25
        sub    $'A',%r9d
        # Skip invalid (out of range) entries
        cmpl $25,%eax
        ja   .Lnext
        cmpl $25,%r9d
        ja   .Lnext
        # Apply symmetric link
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
        # --- Prologue (setup frame and stack alignment) ------------------------
        push %rbp
        .seh_pushreg %rbp
        mov  %rsp,%rbp
        .seh_setframe %rbp,0
        push %r14
        .seh_pushreg %r14
        # Reserve 360 bytes stack space (ensures 16B alignment + local buffers)
        # Win64 ABI: callees expect +32 bytes shadow space
        subq $360,%rsp
        .seh_stackalloc 360
        .seh_endprologue

        # --- Banner / Startup message ------------------------------------------
        leaq fmt_start(%rip),%rcx        # RCX = address of banner format string
        xor  %eax,%eax                   # Clear AL for varargs call (Win64)
        call printf                      # printf(fmt_start)

        # === Prompt user for mode (Encrypt/Decrypt) ============================
        leaq   fmt_mode(%rip), %rcx      # "[E=encrypt / D=decrypt]: "
        xor    %eax, %eax
        call   printf
.readm:
        call   getchar                   # Read a single character
        cmp    $-1, %eax                 # EOF?
        je     .mode_default
        cmp    $'\r', %al                # CR?
        je     .mode_default
        cmp    $'\n', %al                # LF?
        je     .mode_default

        # Convert lowercase to uppercase
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
        jmp    .readm                    # Invalid input -> retry

.setE:
        movb   $'E', mode_ch(%rip)       # Save mode = Encrypt
        jmp    .after_mode
.setD:
        movb   $'D', mode_ch(%rip)       # Save mode = Decrypt
        jmp    .after_mode
.mode_default:
        movb   $'E', mode_ch(%rip)       # Default to Encrypt if none entered
.after_mode:
        # Consume the rest of the line (flush input buffer until CR/LF)
.eatm:
        call   getchar
        cmp    $-1, %eax
        je     .eat_done
        cmp    $'\n', %al
        je     .eat_done
        cmp    $'\r', %al
        jne    .eatm
        # Optional: discard following LF in CRLF sequence
        call   getchar
.eat_done:

        # --- Initialize Enigma state buffer ------------------------------------
        leaq 32(%rsp),%r14               # R14 = pointer to Enigma struct (E)
        mov  %r14,%rcx
        mov  $E_SIZE,%rdx                # Zero out E structure
        call memzero

# ==== Load YAML configuration (loop until success) ============================
.cfg_try:
        lea   cfg_path(%rip), %rcx       # RCX = "config.yaml"
        mov   %r14, %rdx                 # RDX = &E (destination)
        lea   err_line(%rip), %r8        # R8  = &err_line
        call  yaml_apply                 # Parse config -> rc in EAX

        test  %eax, %eax
        jns   .cfg_ok                    # rc >= 0 -> success

        # On parse failure, show message and wait for ENTER
        lea   fmt_cfg_err(%rip), %rcx    # "[SETTINGS] parse failed..."
        mov   %eax, %edx                 # %edx = error code
        mov   err_line(%rip), %r8d       # %r8d = line number
        xor   %eax, %eax
        call  printf

.Lwait_enter_main:
        call  getchar                    # Wait until user presses ENTER
        cmp   $'\n', %al
        jne   .Lwait_enter_main
        jmp   .cfg_try                   # Retry config load

.cfg_ok:
        # Configuration loaded successfully
        leaq   fmt_cfg_ok(%rip), %rcx    # "[SETTINGS] OK"
        xor    %eax, %eax
        call   printf

        # --- Show prompt depending on mode (E or D) ----------------------------
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

# ==== Read user input line =====================================================
.read_line:
        leaq  inbuf(%rip), %rdi          # Destination buffer
        xor   %ecx, %ecx                 # ECX = char count = 0
.read_loop:
        call  getchar
        cmp   $-1, %eax                  # EOF -> stop
        je    .rd_done
        cmp   $'\r', %al                 # CR -> stop
        je    .rd_done
        cmp   $'\n', %al                 # LF -> stop
        je    .rd_done
        cmp   $1023, %ecx                # Max 1023 chars
        jge   .read_loop
        movb  %al, (%rdi)
        inc   %rdi
        inc   %ecx
        jmp   .read_loop
.rd_done:
        movb  $0, (%rdi)                 # Null-terminate input

        # === Encrypt/Decrypt process with live HUD =============================
        leaq  inbuf(%rip),  %rsi         # RSI = input (plaintext/ciphertext)
        leaq  outbuf(%rip), %rdi         # RDI = output buffer

.enc_loop:
        movzbl (%rsi), %edx              # Load next input char
        testb  %dl, %dl
        je     .enc_end                  # End if null terminator

        mov    %r14, %rcx                # RCX = &E
        call   enc_char_m4               # Encrypt/Decrypt char -> AL
        movb   %al, (%rdi)
        movb   $0, 1(%rdi)               # Null-terminate temp string

        # --- Display current rotor window positions [L M R] --------------------
        movzbl E_L+ROTOR_POS(%r14), %eax # Left rotor window
        addb   $'A', %al
        mov    %eax, %edx
        movzbl E_M+ROTOR_POS(%r14), %eax # Middle rotor
        addb   $'A', %al
        mov    %eax, %r8d
        movzbl E_R+ROTOR_POS(%r14), %eax # Right rotor
        addb   $'A', %al
        mov    %eax, %r9d

        # --- Display live header (CT/PT) ---------------------------------------
        movzbl mode_ch(%rip), %eax
        cmp    $'D', %al
        je     .hdr_pt
        leaq   fmt_live_hdr_E(%rip), %rcx # "[L M R] CT: "
        xor    %eax, %eax
        call   printf
        jmp    .hdr_done
.hdr_pt:
        leaq   fmt_live_hdr_D(%rip), %rcx # "[L M R] PT: "
        xor    %eax, %eax
        call   printf

.hdr_done:
        # Print current output character
        leaq   fmt_live_ct(%rip), %rcx   # "%s"
        leaq   outbuf(%rip), %rdx
        xor    %eax, %eax
        call   printf

        # Flush and add small delay for HUD effect
        xor    %rcx, %rcx                # fflush(NULL)
        call   fflush
        mov    $SPEED_MS, %ecx           # Sleep delay (ms)
        call   Sleep

        incq   %rsi                      # Advance input pointer
        incq   %rdi                      # Advance output pointer
        jmp    .enc_loop

.enc_end:
        # --- Print newline after encryption loop -------------------------------
        leaq   fmt_nl(%rip), %rcx
        xor    %eax, %eax
        call   printf

        # === Print final summary line ==========================================
        leaq   fmt_result_md(%rip), %rcx # "[E] PT -> CT" or "[D] CT -> PT"
        movzbl mode_ch(%rip), %edx
        leaq   inbuf(%rip),  %r8         # Input text
        leaq   outbuf(%rip), %r9         # Output text
        xor    %eax, %eax
        call   printf

        # --- Epilogue (restore registers and return) ---------------------------
        addq $360,%rsp
        pop  %r14
        pop  %rbp
        xor  %eax,%eax                   # Return 0
        ret

        .seh_endproc
