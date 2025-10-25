# Enigma M4 (Kriegsmarine) — x86-64 / GAS (AT&T) / Windows (MinGW-w64)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

This project is a console implementation of the **Enigma M4** cipher machine, written in x86-64 assembly (AT&T syntax).
On startup it loads a YAML config, initializes the machine (rotors, rings, Greek wheel, reflector, plugboard), and then encrypts/decrypts a line of text while showing a live HUD.

---

## Build & Run

```bash
# MinGW-w64 (Windows)
x86_64-w64-mingw32-gcc -O2 -s -x assembler .\enigma_m4.asm -o .\enigma_m4.exe

# Run
.\enigma_m4
```

* Mode prompt: `E` (Encrypt) / `D` (Decrypt). Default is `E` if you just press Enter.
* The program keeps trying to load `enigma_setting.yml` until it succeeds.
* It processes up to 1023 bytes, updating a HUD per character: `\r[L M R] CT/PT: ...`.
* Letters `a..z` are auto-uppercased; **non-letters pass through unchanged**.
* Typing feel delay: `SPEED_MS = 180 ms` (tweak in source if desired).

---

## Configuration: `enigma_setting.yml`

### File format

* Encoding: **UTF-8**. A **UTF-8 BOM on the first line is accepted**. **UTF-16 BOMs are rejected**.
* Comments: text after `#` on a line is ignored.
* YAML doc-start `---` is ignored.
* The key–value colon may be **ASCII `:`** or **full-width colon (U+FF1A)**.
* Token separators allowed in values: **space, tab, comma** (also applies to plugboard pairs).

### Supported keys & value rules

| Key              | Value                                       | Notes                                                                                                     |
| ---------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `rotors`         | **Three** Roman numerals: `I..VIII`         | **Order = L M R**                                                                                         |
| `rings`          | **Three letters**: `A..Z`                   | **Order = L M R** (Ringstellung)                                                                          |
| `positions`      | **Three letters**: `A..Z`                   | **Order = L M R** (window/starting position)                                                              |
| `greek`          | `B` or `G`                                  | Beta (β)=`B`, Gamma (γ)=`G`                                                                               |
| `greek_ring`     | Single letter `A..Z`                        | Ring for Greek wheel                                                                                      |
| `greek_position` | Single letter `A..Z`                        | Position for Greek wheel                                                                                  |
| `reflector`      | `B` or `C` **or** any string containing `C` | Thin reflector: **Thin B/C**. If value contains `C/c` (e.g., `C`, `UKW-C`) it’s treated as C; otherwise B |
| `plugboard`      | Up to 10 pairs of letters                   | Example: `AB CD EF` or `AB,CD,EF`. **No duplicates, no self-pairs**, max 10 pairs                         |

> Notes: The M4 **Greek wheel (β/γ) does not step**, but its ring/position offsets still affect the path.
> Double-stepping is implemented per the historical **middle rotor turnover** logic.

### Example configuration

Below is your example converted into a program-friendly YAML file:

```yaml
# enigma_setting.yml
rotors: III VI IV
greek: G
reflector: UKW-C        # contains 'C' → treated as Thin C
rings: A A A            # L M R
positions: F E Y        # L M R
greek_ring: A
greek_position: P
plugboard: AT BL CM DQ ER FG HN IX JO KP
```

* `reflector`: any value **containing `C`** is interpreted as Thin C (e.g., `C`, `UKW-C`, `thin c`).
* `plugboard`: spaces/tabs/commas are all fine. **Max 10 pairs**. Reusing a letter or `AA`-style self-pair triggers an error.

---

## Runtime flow

1. Load config: keep retrying until `enigma_setting.yml` parses successfully.
2. Per-char pipeline:

   * Uppercase → **step_m4** → **plug in** → **R→M→L→Greek (forward)** → **reflect** → **Greek→L→M→R (backward)** → **plug out** → emit.
3. HUD: after each char, print `\r[L M R] CT/PT: ...` with the current window letters.
4. Final summary: `[E] <PT> -> <CT>` or `[D] <CT> -> <PT>`.

---

## Parse errors & troubleshooting

On failure the parser prints:

```
[SETTINGS] parse failed (code <negative>, line <n>). Fix and press ENTER to retry...
```

Common error codes:

* `-1 (ERR_OPEN)`: cannot open config file (path/permissions).
* `-2 (ERR_SYNTAX)`: encoding/BOM/syntax problem (ensure UTF-8; UTF-16 BOM is invalid).
* `-3 (ERR_ROTOR_NAME)`: bad `rotors` token (`I..VIII`) or out-of-range index.
* `-4 (ERR_GREEK)`: `greek` must be `B` or `G`.
* `-5 (ERR_REFLECTOR)`: reflector parsing problem (value should contain `C` for Thin C, otherwise Thin B).
* `-6 (ERR_RINGS)`: `rings` must be exactly three `A..Z` letters.
* `-7 (ERR_POSITIONS)`: `positions` must be exactly three `A..Z` letters.
* `-8 (ERR_GREEK_RING)`: `greek_ring` must be one `A..Z` letter.
* `-9 (ERR_GREEK_POS)`: `greek_position` must be one `A..Z` letter.
* `-10 (ERR_PLUG_TOKEN)`: malformed plugboard pair (range/self-pair/format).
* `-11 (ERR_PLUG_DUP)`: letter reused across pairs.
* `-12 (ERR_PLUG_MANY)`: more than **10** plugboard pairs.
* `-13 (ERR_MISSING)`: one or more required keys are missing. **Required**: `rotors`, `rings`, `positions`, `greek`, `reflector`.

Tips:

* Ensure the file is saved as **UTF-8**, not UTF-16.
* `rotors` must have **exactly three** Roman numerals in **L M R** order.
* Reflector: `C` or anything containing `C` ⇒ Thin C; otherwise Thin B.
* Plugboard must not reuse letters and must have at most 10 pairs.

---

## Implementation notes (dev-oriented)

* Rotor struct: 56 bytes (forward table 26, inverse 26, notches 2, ring 1, pos 1).
* Enigma buffer: 288 bytes (R / M / L / Greek / Reflector / Plugboard).
* Signal path: `PB → R.fwd → M.fwd → L.fwd → Greek.fwd → REF → Greek.bwd → L.bwd → M.bwd → R.bwd → PB`.
* Double-step: triggers when `(POS − RING) mod 26` equals notch A/B.
* All modulo-26 wraps are branchless (CMOV) for stable timing.

---

## Example session

```
[M4] starting...
Mode [E=encrypt / D=decrypt]: E
[SETTINGS] loaded from enigma_setting.yml
Enter plaintext:
[L M R] CT: ...
...
[E] HELLO WORLD -> ZD...   (example)
```

---

## License
[MIT License](./LICENSE)
