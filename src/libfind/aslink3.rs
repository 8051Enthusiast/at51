use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{
        digit1, hex_digit1, line_ending, multispace0, none_of, oct_digit1, one_of, space0, space1,
    },
    combinator::{map, map_res, opt, verify},
    multi::{fold_many0, fold_many_m_n, many0, many1},
    sequence::{delimited, preceded, tuple},
    IResult,
};

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

fn format_spec(i: &str) -> IResult<&str, (Radix, Endian, u8)> {
    delimited(
        multispace0,
        tuple((
            map(one_of("XDQ"), |x| match x {
                'X' => Radix::Hex,
                'D' => Radix::Dec,
                'Q' => Radix::Oct,
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
        space0
    )(i)
}

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

fn parse_byte(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, u8> {
    move |i| map_res(parse_number(format_tuple), std::convert::TryFrom::try_from)(i)
}

fn space_list_many1<'a, T, U>(f: U) -> impl Fn(&'a str) -> IResult<&'a str, Vec<T>>
where
    U: Fn(&'a str) -> IResult<&'a str, T>,
    T: Clone,
{
    move |i| {
        f(i).and_then(|(j, n)| {
            fold_many0(preceded(space1, &f), vec![n], |mut m, k| {
                m.push(k);
                m
            })(j)
        })
    }
}

// note: includes space at beginning
fn space_list_many0<'a, T, U>(f: U) -> impl Fn(&'a str) -> IResult<&'a str, Vec<T>>
where
    U: Fn(&'a str) -> IResult<&'a str, T>,
    T: Clone,
{
    move |i| {
        map(
            opt(preceded(space1,space_list_many1(&f))),
            |x| x.unwrap_or(vec![])
        )(i)
    }
}

fn parse_byte_list(
    format_tuple: (Radix, Endian, u8),
    number_of_bytes: UAddress,
) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    move |i| {
        if number_of_bytes == 0 {
            return Ok((i, vec![]));
        }
        parse_byte(format_tuple)(i).and_then(|(j, n)| {
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

// note: includes space at beginning
fn parse_byte_many(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, Vec<u8>> {
    move |i| space_list_many0(parse_byte(format_tuple))(i)
}

fn parse_multi_number(
    format_tuple: (Radix, Endian, u8),
) -> impl Fn(&str) -> IResult<&str, UAddress> {
    move |i| {
        let (_, ord, len) = format_tuple;
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

fn parse_symbol(i: &str) -> IResult<&str, String> {
    map(many1(none_of(" \t\n\r")), |v| {
        v.into_iter().collect::<String>()
    })(i)
}

fn parse_area_index(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, u16> {
    move |i| {
        let (rad, end, _) = format_tuple;
        map_res(
            parse_multi_number((rad, end, 2)),
            std::convert::TryFrom::try_from,
        )(i)
    }
}
#[derive(Debug, PartialEq)]
struct Aslink3Area {
    name: String,
    size: UAddress,
    absolute: bool,
    code: bool,
    base: Option<UAddress>,
}

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
                code: (flags & 0x20) != 0,
                base: addr.map(|(_, _, _, x)| x),
            },
        )(i)
    }
}

#[derive(Debug, PartialEq)]
struct Aslink3Content {
    offset: UAddress,
    bytes: Vec<u8>,
}

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

fn parse_extended_mode(format_tuple: (Radix, Endian, u8)) -> impl Fn(&str) -> IResult<&str, u16> {
    move |i| {
        alt((
            map(
                verify(parse_byte(format_tuple), |x| x & 0xF0 != 0xF0),
                u16::from,
            ),
            map(parse_area_index(format_tuple), |x| x & 0x0FFF),
        ))(i)
    }
}

// note: includes space at beginning
fn parse_reloc_frag(
    format_tuple: (Radix, Endian, u8),
) -> impl Fn(&str) -> IResult<&str, Vec<Aslink3RelFrag>> {
    move |i| {
        space_list_many0(map(
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
        ))(i)
    }
}
#[derive(Debug, PartialEq, Clone)]
struct Aslink3RelFrag {
    mode: u16,
    offset: u8,
    symarea: u16,
}

#[derive(Debug, PartialEq)]
struct Aslink3Rel {
    content: Aslink3Content,
    area: u16,
    frags: Vec<Aslink3RelFrag>,
}

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

#[derive(PartialEq,Debug)]
struct Aslink3Mod {
    areas: Vec<Aslink3Area>,
    syms: Vec<Aslink3Symdr>,
    rels: Vec<Aslink3Rel>,
}

enum AreaSyms {
    Area(Aslink3Area),
    Sym(Aslink3Symdr),
    Other(()),
}

fn nl<'a, T, U>(f: U) -> impl Fn(&'a str) -> IResult<&'a str, T>
where
    U: Fn(&'a str) -> IResult<&'a str, T>,
{
    move |i| delimited(line_ending, &f, space0)(i)
}

fn ignore_line(chars: &'static str) -> impl Fn(&str) -> IResult<&str, ()> {
    move |i| map(preceded(one_of(chars), many1(none_of("\r\n"))), |_| ())(i)
}

fn parse_module(i: &str) -> IResult<&str, Aslink3Mod> {
    format_spec(i).and_then(|(j, form)| {
        map(
            tuple((
                many0(alt((
                    map(nl(ignore_line("OHM")), AreaSyms::Other),
                    map(nl(parse_area(form)), AreaSyms::Area),
                    map(nl(parse_symdefref(form)), AreaSyms::Sym),
                ))),
                many1(alt((
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
                    areas: area_vec,
                    syms: sym_vec,
                    rels: rels.into_iter().filter_map(|x| x).collect(),
                }
            },
        )(j)
    })
}

pub struct Aslink3Objects {
    objects: Vec<Aslink3Mod>
}

impl Aslink3Objects {
    fn new(buf: &[u8]) {

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
                            mode: 0x101,
                            offset: 0x06,
                            symarea: 0x18
                        },
                        Aslink3RelFrag {
                            mode: 0x181,
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
            parse_reloc((Radix::Hex, Endian::Big, 3))("\
T 00 00 00
R 00 00 00 02"
            ),
            Ok(("",
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
