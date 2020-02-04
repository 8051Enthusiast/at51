Current dev
===========
* Added new statistic "jump-align" which counts the percentage of instructions that jump to unaligned addresses
* Tried to improve documentation

0.3.0 (2019-10-17)
==================
* Implement Aslink3/sdcc library files 
* Removed giant messy regex (and regex dependency)
* Added JSON output

0.2.0 (2019-10-03)
==================
* Added the case where the public references a function points to are not present, which is shown by square brackets
* If there are multiple symbols matched on the same location, only show the ones with the highest goodness
