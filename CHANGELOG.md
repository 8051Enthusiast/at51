1.0.0 (dev)
==================
* Arbitrarily decide that this version is 1.0.0 because it has been stable enough
* Add line to libfind output indicating the file (the way command line arguments are handled could lead to confusion)
* Update dependencies

0.4.2 (2021-06-06)
==================
* Fix ambiguous parse for Keil library names that contain `LDIDATA` (was parsed as `LDI` `DATA`, should have been `LD` `IDATA`, the `DATA` space is actually not contained anywhere in the Keil libs)
* Updated dependencies (newer rustfft version means that `base` is sped up, but it works almost instantly anyway)

0.4.1 (2020-04-15)
==================
* Fix debian not being able to compile because of new library features (fixes #3)

0.4.0 (2020-03-14)
==================
* Added new statistic "jump-align" which counts the percentage of instructions that jump to unaligned addresses
* Tried to improve documentation
* Changed `base` to use non-cyclic mode by default (meaning that firmware doesn't wrap on 0x10000 when searching for alignment), old cyclic mode can be accessed with `--cyclic`
* Added `--dump` to base, which dumps the likeliness of every possible offset
* Added rudimentary config for libfind libraries and stat mode

0.3.0 (2019-10-17)
==================
* Implement Aslink3/sdcc library files 
* Removed giant messy regex (and regex dependency)
* Added JSON output

0.2.0 (2019-10-03)
==================
* Added the case where the public references a function points to are not present, which is shown by square brackets
* If there are multiple symbols matched on the same location, only show the ones with the highest goodness
