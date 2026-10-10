package main

import "image/color"

// The menu-bar icon, 16×16: a padlock whose body is a seal's face, with the
// keyhole for its nose. '#' is drawn, '.' is clear.
const menuBar = `
................
.....######.....
....########....
...###....###...
...##......##...
...##......##...
.##############.
################
###..######..###
###..######..###
######....######
#######..#######
.######..######.
.##############.
..############..
................
`

// The same padlock with a "!" in the corner, for when the menu has a warning.
const menuBarWarning = `
..............##
.....######...##
....########..##
...###....###...
...##......##.##
...##......##...
.##############.
################
###..######..###
###..######..###
######....######
#######..#######
.######..######.
.##############.
..############..
................
`

var templatePalette = map[rune]color.NRGBA{
	'.': {},
	'#': {0, 0, 0, 255},
}

// The app icon, 32×32: the same padlock-seal, a steel shackle over a grey
// face with whiskers, on a rounded navy square.
const appIcon = `
....nnnnnnnnnnnnnnnnnnnnnnnn....
...nnnnnnnnnnnnnnnnnnnnnnnnnn...
..nnnnnnnnnnnnnnnnnnnnnnnnnnnn..
.nnnnnnnnnnnnnnnnnnnnnnnnnnnnnn.
nnnnnnnnnnnnSSSSSSSSnnnnnnnnnnnn
nnnnnnnnnnnSssssssssSnnnnnnnnnnn
nnnnnnnnnnSssSSSSSSssSnnnnnnnnnn
nnnnnnnnnSssSnnnnnnSssSnnnnnnnnn
nnnnnnnnnSsSnnnnnnnnSsSnnnnnnnnn
nnnnnnnnnSsSnnnnnnnnSsSnnnnnnnnn
nnnnnnnnSssSnnnnnnnnSssSnnnnnnnn
nnnnnnnnSssSnnnnnnnnSssSnnnnnnnn
nnnnnnnnSooooooooooooooSnnnnnnnn
nnnnnnnooggggggggggggggoonnnnnnn
nnnnnnoggggggggggggggggggonnnnnn
nnnnnnoggggggggggggggggggonnnnnn
nnnnnoggggggggggggggggggggonnnnn
nnnnnoggggwkggggggggwkggggonnnnn
nnnnnoggggkkggggggggkkggggonnnnn
nnnnnogggggggllllllgggggggonnnnn
nnnnnoggpggllllkkllllggpggonnnnn
nnnnnogoggllllkkkkllllggogonnnnn
nnnnnoggoglllllkklllllgoggonnnnn
nnnnnogogglllllkklllllggogonnnnn
nnnnnnoggggllllkkllllggggonnnnnn
nnnnnnoggggggllllllggggggonnnnnn
nnnnnNNooggggggggggggggooNNnnnnn
nnNNNNNNNooooooooooooooNNNNNNNnn
.NNNNNNNNNNNNNNNNNNNNNNNNNNNNNN.
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
.NNNNNNNNNNNNNNNNNNNNNNNNNNNNNN.
`

var appPalette = map[rune]color.NRGBA{
	'.': {},
	'n': {38, 52, 92, 255},    // background
	'N': {55, 74, 125, 255},   // the face's shadow
	's': {190, 198, 210, 255}, // shackle
	'S': {95, 105, 125, 255},  // shackle outline
	'o': {45, 55, 75, 255},    // outline and whiskers
	'g': {125, 140, 165, 255}, // seal
	'l': {205, 214, 228, 255}, // muzzle
	'k': {30, 34, 48, 255},    // eyes, and the keyhole nose
	'w': {255, 255, 255, 255}, // eye shine
	'p': {245, 150, 170, 255}, // cheeks
}
