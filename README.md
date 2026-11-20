# Ghidra Prospero

Ghidra extension for PlayStation 5 (Prospero) software. 
That plugin is derived from existing IDA and Ghidra loaders/scripts.Credit for those works is listed at the end.

## What it loads

* **Prospero ELF / Prospero SELF:** PS5 eboots and modules (`eboot.bin`,
  `.prx`, `.sprx`), as plain ELF or as decrypted SELF. Only ELF ABI version 2
  or 3 (PS5) is accepted,PS4 files (ABI version 0) are left to Ghidra's own
  ELF loader. Encrypted SELFs are reported as encrypted.
* Imports are placed under their library (`libkernel`, `libSceAgc`, ...)
  from the PS5 `DT_SCE_IMPORT_LIB_1` tags, and NIDs are named from
  `data/nid_db.xml` by the NID Resolver analyzer.
* PS5 segments are named: `.data.rel.ro` (the writable `PT_LOAD` covered by
  `PT_GNU_RELRO`), `.sce_dynlib_data` (the `PT_LOAD` with no access flags that
  holds the dynamic linking data), `.note`, `.sce_process_param`.

The kernel, syscall and firmware container support (PUP, SLB2, sflash, EMC
IPL) is still the PS4 code from GhidraOrbis, it has not been adapted to PS5
yet.

## Requirements

* Ghidra 12.0+

## Credits

* Andrew Strelsky for the [GhidraOrbis plugin](https://github.com/astrelsky/GhidraOrbis)
* SocraticBliss - [PS4 Module Loader](https://github.com/SocraticBliss/ps4_module_loader), [PS4 Kernel Loader](https://github.com/SocraticBliss/ps4_kernel_loader), [PS4 Decrypted PUP Information](https://github.com/SocraticBliss/ps4_dec_pup_info)
* jogolden - [Ghidra PS4 Loader](https://github.com/jogolden/GhidraPS4Loader)
* Z80
* aerosoul
* balika011
* Znullptr
* Pablo (kozarovv)
* ChendoChap
* xyz
* CelesteBlue
* kiwidog
* motoharu
* noname120
* flatz
* Team Reswitched
* zecoxao
