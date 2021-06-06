//! This module parses aslink3 modules.
//!
//! This is used within the libraries used by the sdcc compiler.
//! It is a 'human readable format' in that it only consists of printable characters,
//! but it is mostly bytes encoded as numbers and a few strings.
//! Note that the sdcc library files themselves are ont aslink3 modules but are BSD ar archives
//! that contain the aslink3 modules.
use ar::Archive;
use bitflags::bitflags;
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{
        digit1, hex_digit1, line_ending, multispace0, none_of, oct_digit1, one_of, space0, space1,
    },
    combinator::{map, map_opt, map_res, opt, verify},
    multi::{fold_many_m_n, many0, many1, separated_list0, separated_list1},
    sequence::{delimited, preceded, tuple},
    IResult,
};
use std::io::{Error, ErrorKind, Read};

type UAddress = u32;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Radix {
    Hex,
    Dec,
    Oct,
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum Endian {
    Big,
    Little,
}

// at the top of each module is a triple which specifies the radix, endianness and length of
// integers
// for example, with "XH2" the string "01 02" evaluates to 0x0102
fn format_spec(i: &str) -> IResult<&str, (Radix, Endian, u8)> {
    delimited(
        multispace0,
        tuple((
            map(one_of("XDQ"), |x| match x {
                'X' => Radix::Hex,
                'D' => Radix::Dec,
                'Q' => Radix::Oct,
                // unreachable because the char is one_of("XDQ")
                _ => unreachable!(),
            }),
            map(one_of("HL"), |x| match x {
                'H' => Endian::Big,
                'L' => Endian::Little,
                _ => unreachable!(),
            }),
            map(one_of("234"), |x| match x {
                '2' => 2,
                '3' => 3,
                '4' => 4,
                _ => unreachable!(),
            }),
        )),
        space0,
    )(i)
}

// this parses a single, contiguous number
// note that "01 02" is not considered contiguous but is sometimes considered as a single number
fn parse_number(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, UAddress> {
    move |i| {
        let (radix, _, _) = format_tuple;
        match radix {
            Radix::Hex => map_res(hex_digit1, |n| UAddress::from_str_radix(n, 16))(i),
            Radix::Dec => map_res(digit1, |n| UAddress::from_str_radix(n, 10))(i),
            Radix::Oct => map_res(oct_digit1, |n| UAddress::from_str_radix(n, 8))(i),
        }
    }
}

// parse a single byte (the number of the number has to be below 256)
fn parse_byte(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, u8> {
    move |i| map_res(parse_number(format_tuple), std::convert::TryFrom::try_from)(i)
}

// a list with a given number of bytes
fn parse_byte_list(
    format_tuple: (Radix, Endian, u8),
    number_of_bytes: UAddress,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    move |i| {
        if number_of_bytes == 0 {
            return Ok((i, vec![]));
        }
        // parse the first element
        parse_byte(format_tuple)(i).and_then(|(j, n)| {
            // and then exactly n-1 subsequent ones, folding them
            // into a vector
            fold_many_m_n(
                (number_of_bytes - 1) as usize,
                (number_of_bytes - 1) as usize,
                preceded(space1, parse_byte(format_tuple)),
                vec![n],
                |mut m, k| {
                    m.push(k);
                    m
                },
            )(j)
        })
    }
}

// parses as many bytes as possible
// note: includes space at beginning
fn parse_byte_many(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    move |i| separated_list1(space1, parse_byte(format_tuple))(i)
}

// parses a number that is split into multiple bytes
fn parse_multi_number(
    format_tuple: (Radix, Endian, u8),
) -> impl Fn(&str) -> IResult<&str, UAddress> {
    move |i| {
        let (_, ord, len) = format_tuple;
        // holder-like number conversion for folding
        let folder = |acc, n: &u8| acc * 256 + UAddress::from(*n);
        map(
            parse_byte_list(format_tuple, UAddress::from(len)),
            move |v| match ord {
                Endian::Big => v.iter().fold(0, folder),
                Endian::Little => v.iter().rfold(0, folder),
            },
        )(i)
    }
}

// parse a symbol (as in linking symbol)
fn parse_symbol(i: &str) -> IResult<&str, String> {
    // we accept everything except whitespace
    map(many1(none_of(" \t\n\r")), |v| {
        v.into_iter().collect::<String>()
    })(i)
}

// an area index is really just a 2-byte number
fn parse_area_index(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, u16> {
    move |i| {
        let (rad, end, _) = format_tuple;
        map_res(
            parse_multi_number((rad, end, 2)),
            std::convert::TryFrom::try_from,
        )(i)
    }
}

// similar to OMF-51 segments if that's of any help
// (I've been told not many people have in-depth knowledge of 8051-related object formats)
#[derive(Debug, PartialEq)]
struct Aslink3Area {
    name: String,
    size: UAddress,
    absolute: bool,
    code: bool,
    base: Option<UAddress>,
}

// parses an area string, typically looks like
// "A CSEG size 84A flags 20 addr 0"
fn parse_area(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, Aslink3Area> {
    move |i| {
        map(
            tuple((
                tag("A"),
                space1,
                parse_symbol,
                space1,
                tag("size"),
                space1,
                parse_number(format_tuple),
                space1,
                tag("flags"),
                space1,
                parse_number(format_tuple),
                // the addr part doesn't seem to be in the official specification
                // but it is almost included with sdcc libraries and 0 for relocatable
                // areas
                opt(tuple((
                    space1,
                    tag("addr"),
                    space1,
                    parse_number(format_tuple),
                ))),
            )),
            |(_, _, name, _, _, _, size, _, _, _, flags, addr)| Aslink3Area {
                name,
                size,
                absolute: (flags & 0x08) != 0,
                // this is also an sdld-extension and specific to 8051
                // and tells us that this area belongs to the code space
                code: (flags & 0x20) != 0,
                base: addr.map(|(_, _, _, x)| x),
            },
        )(i)
    }
}

// offset is from beginning of area
// note that the length of bytes may be bigger
// than the area since the size is reduced when relocations are applied
#[derive(Debug, PartialEq)]
struct Aslink3Content {
    offset: UAddress,
    bytes: Vec<u8>,
}

// parse a content line, which looks (assuming XH3) like
// T 00 02 56 BB 48 03 02 01 7F
// the first 3 bytes are the offset (0x256 in this case)
// the rest defines the content
// note that this style of T-line is always followed by a R-line
// if it is followed by a P-line, it is a different format
fn parse_content(
    format_tuple: (Radix, Endian, u8),
) -> impl Fn(&str) -> IResult<&str, Aslink3Content> {
    move |i| {
        map(
            tuple((
                tag("T"),
                space1,
                parse_multi_number(format_tuple),
                parse_byte_many(format_tuple),
            )),
            |(_, _, offset, bytes)| Aslink3Content { offset, bytes },
        )(i)
    }
}
enum JumpType {
    Addr24,
    Addr19,
    Addr16,
    Addr11,
    Byte,  // we only follow these if they're pc-relative
    Other, // we don't follow these
}

// small helper function to convert a given vector of bytes to a number
// considering endianness
fn endian_to_number(endian: Endian, len: u8, buf: &[u8]) -> usize {
    match endian {
        Endian::Big => buf
            .iter()
            .take(usize::from(len))
            .fold(0, |acc, x| acc * 256 + usize::from(*x)),
        Endian::Little => buf[..usize::from(len)]
            .iter()
            .rev()
            .fold(0, |acc, x| acc * 256 + usize::from(*x)),
    }
}

// the mode bitflags of the relocations carry information on how the relocation is applied to the
// address
bitflags! {
    struct Mode: u16 {
        const BYTE = 1;           // relocation is a byte (default: word)
        const SYMBOL = 1<<1;      // references symbol (default: area)
        const PC_RELATIVE = 1<<2; // pc-relative (default: absolute)
        const TWO_BYTES = 1<<3;   // two bytes, of which one is chosen
        const UNSIGNED = 1<<4;    // unsigned (default signed)
        const PAGE_0 = 1<<5;      // page 0 (don't ask, I don't know what this means)
        const PAGE_NN = 1<<6;     // page 'nn'
        const CHOOSE_2 = 1<<7;    // choose the second byte (default: first)
                                  // this is called MSB in the original implementation
                                  // even if it is the second of three bytes in an address
        const THREE_BYTES = 1<<8; // relocation is 24-bit word
        const CHOOSE_3 = 1<<9;    // choose the third byte (default: first or second)
        const BITS = 1 << 10;     // convert to bit address (irrelevant to this program)
    }
}

impl Mode {
    // the addr11 mode is not directly encoded as a bit, but by making sure that some
    // (in the original version) incompatible bits are set and then some more
    // the same applies to addr19 and addr24
    fn is_addr11(self) -> bool {
        (self & (Mode::BYTE | Mode::TWO_BYTES | Mode::CHOOSE_2)) == Mode::TWO_BYTES
    }
    fn is_addr19(self) -> bool {
        (self & (Mode::BYTE | Mode::TWO_BYTES | Mode::CHOOSE_2))
            == (Mode::TWO_BYTES | Mode::CHOOSE_2)
    }
    fn is_addr24(self) -> bool {
        (self & (Mode::BYTE | Mode::TWO_BYTES | Mode::CHOOSE_2)) == Mode::CHOOSE_2
    }
    fn get_jump_type(self) -> JumpType {
        if self.is_addr19() {
            JumpType::Addr19
        } else if self.is_addr11() {
            JumpType::Addr11
        } else if self.is_addr24() {
            JumpType::Addr24
        // these modes take a multi-byte address and extract one byte
        } else if self.intersects(Mode::THREE_BYTES | Mode::TWO_BYTES) {
            JumpType::Other
        } else if !self.contains(Mode::BYTE) {
            JumpType::Addr16
        } else {
            JumpType::Byte
        }
    }
    // modifies the (u8, u8, bool) array which represents the value, the mask and whether the byte is to
    // be included
    // disables bits where the corresponding byte is modified during linking and disables bytes
    // which are not included at all
    fn modify_cmf_to_fixup(
        self,
        cmf_array: &mut [(u8, u8, bool)],
        format_tuple: (Radix, Endian, u8),
    ) -> usize {
        match self.get_jump_type() {
            JumpType::Addr19 => {
                // the last byte of 4 is the opcode and the first 3 bytes an address
                let (opcode, _, _) = cmf_array[3];
                let ret = endian_to_number(
                    format_tuple.1,
                    3,
                    &[cmf_array[0].0, cmf_array[1].0, cmf_array[2].0],
                );
                cmf_array[0] = (opcode, 0x1f, true);
                cmf_array[1] = (0, 0, true);
                cmf_array[2] = (0, 0, true);
                cmf_array[3] = (0, 0, false);
                ret
            }
            JumpType::Addr11 => {
                // the last byte of 3 is the opcode and the first 2 bytes an address
                let (opcode, _, _) = cmf_array[2];
                let ret = endian_to_number(format_tuple.1, 2, &[cmf_array[0].0, cmf_array[1].0]);
                cmf_array[0] = (opcode, 0x1f, true);
                cmf_array[1] = (0, 0, true);
                cmf_array[2] = (0, 0, false);
                ret
            }
            JumpType::Addr24 => {
                let ret = endian_to_number(
                    format_tuple.1,
                    3,
                    &[cmf_array[0].0, cmf_array[1].0, cmf_array[2].0],
                );
                cmf_array[0] = (0, 0, true);
                cmf_array[1] = (0, 0, true);
                cmf_array[2] = (0, 0, true);
                ret
            }
            JumpType::Other => {
                cmf_array[0] = (0, 0, true);
                cmf_array[1] = (0, 0, false);
                if self.contains(Mode::THREE_BYTES) {
                    cmf_array[2] = (0, 0, false);
                }
                0
            }
            JumpType::Addr16 => {
                let ret = endian_to_number(format_tuple.1, 2, &[cmf_array[0].0, cmf_array[1].0]);
                cmf_array[0] = (0, 0, true);
                cmf_array[1] = (0, 0, true);
                ret
            }
            JumpType::Byte => {
                let ret = usize::from(cmf_array[0].0);
                cmf_array[0] = (0, 0, true);
                ret
            }
        }
    }
    // gets the size of a relocation after linking
    fn get_onsite_size(self) -> usize {
        match self.get_jump_type() {
            JumpType::Addr11 | JumpType::Addr16 => 2,
            JumpType::Addr19 | JumpType::Addr24 => 3,
            JumpType::Other | JumpType::Byte => 1,
        }
    }
    // returns a function from the mode which, given the bytes where the relocation was applied to
    // and the address at which those bytes are, returns the function the bytes refer to
    fn get_fixup_function(
        self,
        format_tuple: (Radix, Endian, u8),
        offset: usize,
    ) -> impl Fn(&[u8], usize) -> usize {
        move |bytes, addr| {
            let jump_type = self.get_jump_type();
            let (_, endian, _) = format_tuple;
            let mut high_bit = 0;
            let mut target_address = match jump_type {
                JumpType::Addr19 => {
                    high_bit = 23;
                    usize::from(bytes[0] & 0xe0) << 16 | endian_to_number(endian, 2, &bytes[1..])
                }
                JumpType::Addr11 => {
                    high_bit = 10;
                    usize::from(bytes[0] & 0xe0) << 8 | usize::from(bytes[1])
                }
                JumpType::Addr24 => {
                    high_bit = 23;
                    endian_to_number(endian, 3, bytes)
                }
                JumpType::Addr16 => {
                    high_bit = 15;
                    endian_to_number(endian, 2, bytes)
                }
                JumpType::Byte => {
                    high_bit = 7;
                    usize::from(bytes[0])
                }
                JumpType::Other => 0,
            };
            let mut offset_signed = offset;
            // make signed if the bits say so
            if !self.contains(Mode::UNSIGNED) {
                if (target_address & 1 << high_bit) != 0 {
                    target_address = target_address.wrapping_sub(2 * (1 << high_bit));
                }
                let offset_high_bit = match self.get_jump_type() {
                    JumpType::Addr11 | JumpType::Addr16 => 15,
                    JumpType::Addr19 | JumpType::Addr24 => 23,
                    JumpType::Byte => 7,
                    JumpType::Other => {
                        if self.contains(Mode::THREE_BYTES) {
                            23
                        } else {
                            15
                        }
                    }
                };
                if (offset & 1 << offset_high_bit) != 0 {
                    offset_signed = offset.wrapping_sub(2 * (1 << offset));
                }
            }
            target_address -= offset_signed;
            // the jump is relative to the current address and not absolute
            if self.contains(Mode::PC_RELATIVE) {
                if self.contains(Mode::BYTE) {
                    target_address -= addr + 1;
                } else {
                    target_address -= addr + 2;
                }

            // addr11 (and addr19) jumps within the same block (relative to pc at next instruction)
            } else if self.is_addr11() {
                target_address = target_address & 0x7ff | (addr + 2) & 0xf800;
            } else if self.is_addr19() {
                target_address = target_address & 0x0007_ffff | (addr + 3) & 0x00f8_0000;
            }
            // extend the addresses to be in same 16-bit (or 24-bit) block as we may be dealing
            // with some banked memory
            match jump_type {
                JumpType::Addr24 | JumpType::Addr19 => {
                    target_address = target_address & 0x00ff_ffff | addr & !0x00ff_ffff;
                }
                _ => {
                    target_address = target_address & 0xffff | addr & !0xffff;
                }
            }
            target_address
        }
    }
}

// the sdld R-line has a feature where the 4 highest bits of the mode byte are enabled as a kind of
// escape so another mode byte follows so that one has effectively a 12-bit mode
fn parse_extended_mode(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, Mode> {
    move |i| {
        map_opt(
            alt((
                map(
                    verify(parse_byte(format_tuple), |x| x & 0xF0 != 0xF0),
                    u16::from,
                ),
                map(
                    parse_area_index((format_tuple.0, Endian::Big, format_tuple.2)),
                    |x| x & 0x0FFF,
                ),
            )),
            Mode::from_bits,
        )(i)
    }
}

#[derive(Debug, PartialEq, Clone)]
struct Aslink3RelFrag {
    mode: Mode,
    offset: u8,
    symarea: u16,
}

// a relocation list, which in each element contains mode, offset and index of area/symbol
// note: includes space at beginning
fn parse_reloc_frag(
    format_tuple: (Radix, Endian, u8),
) -> impl Fn(&str) -> IResult<&str, Vec<Aslink3RelFrag>> {
    move |i| {
        separated_list0(
            space1,
            map(
                tuple((
                    parse_extended_mode(format_tuple),
                    space1,
                    parse_byte(format_tuple),
                    space1,
                    parse_area_index(format_tuple),
                )),
                |(mode, _, offset, _, symarea)| Aslink3RelFrag {
                    mode,
                    offset,
                    symarea,
                },
            ),
        )(i)
    }
}

#[derive(Debug, PartialEq)]
struct Aslink3Rel {
    content: Aslink3Content,
    area: u16,
    frags: Vec<Aslink3RelFrag>,
}

// parses a R-line, which also includes the preceding T-line because it is mandatory and this makes
// it easier
// a R-line (with a T-line) looks like this:
// T 00 02 56 BB 48 03 02 01 7F
// R 00 00 00 17 00 07 00 17
// it always begins with R and two 0 bytes, followed by the area index and the relocations
// the bytes of the T-line thus belong to area 0x17
// note that the offset in the T-line includes the bytes of the offset specified at the beginning
// of the T-line
fn parse_reloc(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, Aslink3Rel> {
    move |i| {
        map(
            tuple((
                parse_content(format_tuple),
                line_ending,
                tag("R"),
                space1,
                verify(parse_area_index(format_tuple), |x| x == &0),
                space1,
                parse_area_index(format_tuple),
                parse_reloc_frag(format_tuple),
            )),
            |(content, _, _, _, _, _, area, frags)| Aslink3Rel {
                content,
                area,
                frags,
            },
        )(i)
    }
}

#[derive(Debug, PartialEq)]
struct Aslink3Symdr {
    symbol: String,
    reference: bool,
    area: Option<u16>,
    value: UAddress,
}

// a symbol definition/reference
// a definition at the beginning without a preceding area is a constant
// a definition after a symbol defines a symbol with the specified offset from the area
// a reference at the beginning includes an external symbol
// I don't know what a reference after an area does, but I haven't seen it yet
fn parse_symdefref(
    format_tuple: (Radix, Endian, u8),
) -> impl Fn(&str) -> IResult<&str, Aslink3Symdr> {
    move |i| {
        map(
            tuple((
                tag("S"),
                space1,
                parse_symbol,
                space1,
                alt((tag("Ref"), tag("Def"))),
                parse_number(format_tuple),
            )),
            |(_, _, symbol, _, refdef, value)| Aslink3Symdr {
                symbol,
                reference: refdef == "Ref",
                area: None,
                value,
            },
        )(i)
    }
}

#[derive(PartialEq, Debug)]
struct Aslink3Mod {
    format: (Radix, Endian, u8),
    areas: Vec<Aslink3Area>,
    syms: Vec<Aslink3Symdr>,
    rels: Vec<Aslink3Rel>,
}

enum AreaSyms {
    Area(Aslink3Area),
    Sym(Aslink3Symdr),
    Other(()),
}

// a wrapper to include newlines at the front and potential space at the end of the line
fn nl<'a, T, U>(f: U) -> impl Fn(&'a str) -> IResult<&'a str, T>
where
    U: Fn(&'a str) -> IResult<&'a str, T>,
{
    move |i| delimited(line_ending, &f, space0)(i)
}

// ignore a line starting with a char out of a set of chars
fn ignore_line(chars: &'static str) -> impl Fn(&str) -> IResult<&str, ()> {
    move |i| map(preceded(one_of(chars), many1(none_of("\r\n"))), |_| ())(i)
}

// parse the whole module
fn parse_module(i: &str) -> IResult<&str, Aslink3Mod> {
    // first we read the header containing the format tuple
    format_spec(i).and_then(|(j, form)| {
        map(
            tuple((
                // the O-line (options), H-line (header) and M-line (module name)
                // are ignored
                // areas and symbols are contained in the first part of the module
                many0(alt((
                    map(nl(ignore_line("OHM")), AreaSyms::Other),
                    map(nl(parse_area(form)), AreaSyms::Area),
                    map(nl(parse_symdefref(form)), AreaSyms::Sym),
                ))),
                // after that come T, R and P lines
                // P lines are ignored since pages are not relevant to the 8051 in sdcc
                many0(alt((
                    map(nl(parse_reloc(form)), Some),
                    map(tuple((nl(ignore_line("T")), nl(ignore_line("P")))), |_| {
                        None
                    }),
                ))),
            )),
            |(arsy, rels)| {
                let mut current_area = None;
                let mut area_vec = Vec::new();
                let mut sym_vec = Vec::new();
                // match the symbols to the corresponding areas
                for x in arsy {
                    match x {
                        AreaSyms::Area(area) => {
                            current_area = match current_area {
                                None => Some(0u16),
                                Some(x) => Some(x + 1),
                            };
                            area_vec.push(area)
                        }
                        AreaSyms::Sym(sym) => sym_vec.push(Aslink3Symdr {
                            area: current_area,
                            ..sym
                        }),
                        AreaSyms::Other(_) => (),
                    }
                }
                Aslink3Mod {
                    format: form,
                    areas: area_vec,
                    syms: sym_vec,
                    rels: rels.into_iter().filter_map(|x| x).collect(),
                }
            },
        )(j)
    })
}

/// Contains the parsed data of an aslink3 (sdld) libary file
pub struct Aslink3Objects {
    objects: Vec<Aslink3Mod>,
}

impl Aslink3Objects {
    /// Reads a Aslink3 library file from a &[u8] buffer
    /// Can result in an IO-Error
    pub fn new(buf: &[u8]) -> Result<Aslink3Objects, Error> {
        // a sdld library is just a BSD ar archive containing a bunch of modules
        let mut /*btw I use*/ arch = Archive::new(buf);
        let mut objarr = Vec::new();
        while let Some(entry_result) = arch.next_entry() {
            let mut entry = entry_result?;
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            // It should be ascii, so just assume it is utf8
            let string = std::str::from_utf8(&buf[..]).or_else(|_| {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid characters in module",
                ))
            })?;
            let (_, parsed_module) = parse_module(string)
                .or_else(|_| Err(Error::new(ErrorKind::InvalidData, "Could not parse module")))?;
            objarr.push(parsed_module);
        }
        Ok(Aslink3Objects { objects: objarr })
    }
}

type Cmf = (Vec<(u8, u8)>, Vec<super::Fixup>);

// a helper function process the relocation
fn process_relocs(
    rel: &Aslink3Rel,
    module: &Aslink3Mod,
    segid_unique_map: &[(u16, usize)],
    content_mask_fixup: &mut Cmf,
) {
    // create a vector containing the assumed valid bytes from the content of the T-line
    let mut con_array: Vec<_> = rel.content.bytes.iter().map(|x| (*x, 0xff, true)).collect();
    // compensate for the fact that the offset of a relocation includes the offset bytes at the
    // beginning of the T-line and not just the content
    let mut full_array = vec![(0, 0, false); usize::from(module.format.2)];
    full_array.append(&mut con_array);
    let mut offset_array = Vec::new();
    for frag in &rel.frags {
        // invalid (at least I hope that it is invalid) relocation into offset
        if frag.offset < module.format.2 {
            continue;
        }
        // apply relocation to content
        offset_array.push(
            frag.mode
                .modify_cmf_to_fixup(&mut full_array[usize::from(frag.offset)..], module.format),
        );
    }
    let (content_mask, fixups) = content_mask_fixup;
    let mut new_content_index = 0;
    let mut cmf_index = rel.content.offset as usize;
    while cmf_index < content_mask.len() && new_content_index < full_array.len() {
        // all relocations that apply to the current offset
        for (i, frag) in rel
            .frags
            .iter()
            .enumerate()
            .filter(|(_, x)| usize::from(x.offset) == new_content_index)
        {
            // we want to be sure that we have all information, which
            // we don't have when only the lowest of three bytes is written
            // to a location
            match frag.mode.get_jump_type() {
                JumpType::Other => continue,
                JumpType::Byte => {
                    if !frag.mode.contains(Mode::PC_RELATIVE) {
                        continue;
                    }
                }
                _ => {
                    // bit locations are not in CODE
                    if frag.mode.contains(Mode::BITS) {
                        continue;
                    }
                }
            }
            // get the CodeRef struct
            let code_ref = if frag.mode.contains(Mode::SYMBOL) {
                let sym = &module.syms[usize::from(frag.symarea)];
                if sym.reference {
                    // if we have a extern symbol, it is a pubref
                    super::CodeRef::new_pubref(sym.symbol.clone(), sym.value as usize)
                } else if let Some(id) = segid_unique_map.iter().find(|(i, _)| Some(*i) == sym.area)
                {
                    // check whether referenced offset is in a code segment
                    if !module.areas[usize::from(id.0)].code {
                        continue;
                    }
                    super::CodeRef::new_segid(id.1, sym.value as usize)
                } else {
                    continue;
                }
            } else if let Some(id) = segid_unique_map.iter().find(|(i, _)| i == &frag.symarea) {
                super::CodeRef::new_segid(id.1, 0)
            } else {
                continue;
            };
            fixups.push(super::Fixup::new(
                cmf_index,
                frag.mode.get_onsite_size(),
                Box::new(frag.mode.get_fixup_function(module.format, offset_array[i])),
                code_ref,
            ));
        }
        let (new_byte, new_mask, do_we_go_on_living) = full_array[new_content_index];
        // skip the deactivated bytes
        if !do_we_go_on_living {
            new_content_index += 1;
            continue;
        }
        // otherwise copy the bytes into the value-mask tuple
        content_mask[cmf_index] = (new_byte, new_mask);
        cmf_index += 1;
        new_content_index += 1;
    }
}

impl std::convert::TryFrom<Aslink3Objects> for super::SegmentCollection {
    type Error = &'static str;
    fn try_from(mods: Aslink3Objects) -> Result<Self, Self::Error> {
        let mut current_segid = 0;
        let mut segment_collection = Vec::new();
        for module in mods.objects {
            // excludes non-code areas and areas with no size, which would
            // just match everywhere
            let relevant_reloc_areas: Vec<_> = module
                .areas
                .iter()
                .enumerate()
                .filter(|(_, area)| area.code && area.size > 0)
                .collect();
            // we want unique segment ids within a library so we can easier
            // check if references are fullfilled
            // therefore we have a map with internal area index -> unique id
            let mut segid_unique_map = Vec::new();
            let mut segid_cmf = Vec::new();
            for (i, ar) in &relevant_reloc_areas {
                let content_mask = vec![(0, 0); ar.size as usize];
                let fixups: Vec<super::Fixup> = Vec::new();
                segid_cmf.push((content_mask, fixups));
                segid_unique_map.push((*i as u16, current_segid));
                current_segid += 1;
            }
            // process all relocations that come from a relevant_reloc_area
            for rel in &module.rels {
                // excludes areas not in relevant_reloc_areas
                if let Some(current_cmf) = &relevant_reloc_areas
                    .iter()
                    .position(|(i, _)| *i == usize::from(rel.area))
                {
                    process_relocs(
                        rel,
                        &module,
                        &segid_unique_map,
                        &mut segid_cmf[*current_cmf],
                    );
                }
            }
            for ((id, area), (con_mask, fixups)) in
                relevant_reloc_areas.into_iter().zip(segid_cmf.into_iter())
            {
                // collect all public symbols for a given area
                let pubsyms = module
                    .syms
                    .iter()
                    .filter(|s| s.area == Some(id as u16))
                    .map(|s| (s.symbol.clone(), s.value as usize))
                    .collect();
                if area.absolute {
                    segment_collection.push(super::Segment::new_absolute(
                        area.base.unwrap_or(0) as usize,
                        con_mask,
                        fixups,
                        pubsyms,
                    ));
                } else {
                    segment_collection
                        .push(super::Segment::new_relocatable(con_mask, fixups, pubsyms));
                }
            }
        }
        Ok(super::SegmentCollection::new(segment_collection))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_spec_test() {
        assert_eq!(
            format_spec("\nDL3"),
            Ok(("", (Radix::Dec, Endian::Little, 3)))
        );
    }
    #[test]
    fn parse_number_test_d() {
        assert_eq!(
            parse_number((Radix::Dec, Endian::Little, 2))("14"),
            Ok(("", 14))
        )
    }
    #[test]
    fn parse_number_test_q() {
        assert_eq!(
            parse_number((Radix::Oct, Endian::Little, 2))("200"),
            Ok(("", 0o200))
        )
    }
    #[test]
    fn parse_number_test_x() {
        assert_eq!(
            parse_number((Radix::Hex, Endian::Little, 2))("deadbeef very dead"),
            Ok((" very dead", 0xdead_beef))
        )
    }
    #[test]
    fn parse_byte_list_test() {
        assert_eq!(
            parse_byte_list((Radix::Hex, Endian::Little, 2), 5)("de ad be ef 10 test"),
            Ok((" test", vec![0xde, 0xad, 0xbe, 0xef, 0x10]))
        )
    }
    #[test]
    fn parse_byte_many_test() {
        assert_eq!(
            parse_byte_many((Radix::Hex, Endian::Little, 2))(" de ad be ef 10\n"),
            Ok(("\n", vec![0xde, 0xad, 0xbe, 0xef, 0x10]))
        )
    }
    #[test]
    fn parse_multi_number_test1() {
        assert_eq!(
            parse_multi_number((Radix::Hex, Endian::Big, 3))("ab cd ef 10 20"),
            Ok((" 10 20", 0x00ab_cdef))
        )
    }
    #[test]
    fn parse_multi_number_test2() {
        assert_eq!(
            parse_multi_number((Radix::Oct, Endian::Little, 4))("10 20 0 4\n"),
            Ok(("\n", 0x0400_1008))
        )
    }
    #[test]
    fn parse_area_test() {
        assert_eq!(
            parse_area((Radix::Hex, Endian::Big, 3))("A CSEG size 38 flags 20 addr 0\n"),
            Ok((
                "\n",
                Aslink3Area {
                    name: String::from("CSEG"),
                    size: 0x38,
                    absolute: false,
                    code: true,
                    base: Some(0)
                }
            ))
        )
    }
    #[test]
    fn parse_content_test() {
        assert_eq!(
            parse_content((Radix::Hex, Endian::Big, 3))(
                "T 00 00 14 E5 00 00 01 30 E7 0D B2 D5 E4 C3 95\n"
            ),
            Ok((
                "\n",
                Aslink3Content {
                    offset: 0x14,
                    bytes: vec![0xe5, 0, 0, 1, 0x30, 0xe7, 0x0d, 0xb2, 0xd5, 0xe4, 0xc3, 0x95]
                }
            ))
        )
    }
    #[test]
    fn parse_reloc_test() {
        assert_eq!(
            parse_reloc((Radix::Hex, Endian::Big, 3))(
                "T 00 00 5C C0 07 74 00 00 0D C0 E0 74 00 00 0D C0\nR 00 00 00 17 F1 01 06 00 18 F1 81 0C 00 18"
            ),
            Ok((
                "",
                Aslink3Rel {
                    content: Aslink3Content {
                        offset: 0x5c,
                        bytes: vec![
                            0xc0, 0x07, 0x74, 0x00, 0x00, 0x0d, 0xc0, 0xe0, 0x74, 0x00, 0x00, 0x0d,
                            0xc0
                        ]
                    },
                    area: 0x17,
                    frags: vec![
                        Aslink3RelFrag {
                            mode: Mode::BYTE | Mode::THREE_BYTES,
                            offset: 0x06,
                            symarea: 0x18
                        },
                        Aslink3RelFrag {
                            mode: Mode::BYTE | Mode::THREE_BYTES | Mode::CHOOSE_2,
                            offset: 0x0c,
                            symarea: 0x18
                        }
                    ]
                }
            ))
        )
    }
    #[test]
    fn parse_reloc_test2() {
        assert_eq!(
            parse_reloc((Radix::Hex, Endian::Big, 3))(
                "\
T 00 00 00
R 00 00 00 02"
            ),
            Ok((
                "",
                Aslink3Rel {
                    content: Aslink3Content {
                        offset: 0,
                        bytes: vec![]
                    },
                    area: 2,
                    frags: vec![]
                }
            ))
        )
    }
    #[test]
    fn parse_symdefref_test() {
        assert_eq!(
            parse_symdefref((Radix::Hex, Endian::Big, 3))("S _SBUF Def000099"),
            Ok((
                "",
                Aslink3Symdr {
                    symbol: String::from("_SBUF"),
                    reference: false,
                    area: None,
                    value: 0x99
                }
            ))
        )
    }
}
