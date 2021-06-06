//! Module for reading the initialization structure found on many
//! firmware images compiled with the Keil C51 compiler.
use nom::{
    bits,
    branch::alt,
    bytes,
    combinator::{map, verify},
    multi::{count, many0},
    number::complete::{be_u16, be_u24, be_u8},
    sequence::{pair, terminated, tuple},
    IResult,
};
use serde::Serialize;

#[derive(Debug, PartialEq)]
enum DataType {
    Idata,
    Xdata,
    Pdata,
    Bit,
    Hdata,
}

#[derive(Debug, PartialEq)]
struct InfoHeader {
    data_type: DataType,
    len: usize,
}

// an info header has a BIG BIT at position 5 which specifies whether the length
// field is 5 bits or 13 bits
fn header_bit(i: (&[u8], usize)) -> IResult<(&[u8], usize), (u8, u8, u16)> {
    alt((
        tuple((
            bits::complete::take(2u8),
            bits::complete::tag(0u8, 1u8),
            bits::complete::take(5u8),
        )),
        tuple((
            bits::complete::take(2u8),
            bits::complete::tag(1u8, 1u8),
            bits::complete::take(13u8),
        )),
    ))(i)
}
fn info_header(i: &[u8]) -> IResult<&[u8], InfoHeader> {
    map(
        verify(
            // note: header_bit moved to separate function to satisfy type checker
            bits::bits(header_bit),
            |x| x != &(0, 0, 0),
        ),
        |(typ, big_bit, len): (u8, u8, u16)| InfoHeader {
            data_type: match (typ, big_bit) {
                (0, _) => DataType::Idata,
                (1, _) => DataType::Xdata,
                (2, _) => DataType::Pdata,
                (3, 0) => DataType::Bit,
                // if BIG BIT is set and the data_type is set as BIT, it is actually HDATA
                (3, 1) => DataType::Hdata,
                // this shouldn't happen because the value is only 2 bits wide
                _ => panic!("A number that shouldn't be out of range is out of range"),
            },
            len: len as usize,
        },
    )(i)
}

#[derive(Debug, PartialEq, Serialize)]
enum InitBlock {
    Idata((u8, Vec<u8>)),
    Xdata((u16, Vec<u8>)),
    Pdata((u8, Vec<u8>)),
    Bit(Vec<(u8, u8)>),
    Hdata((u32, Vec<u8>)),
}

// for bits, the value is stored in the 7th bit and the rest in the lower 7 bits
fn bit_init(i: (&[u8], usize)) -> IResult<(&[u8], usize), (u8, u8)> {
    pair(bits::complete::take(1u8), bits::complete::take(7u8))(i)
}

fn init_block(i: &[u8]) -> IResult<&[u8], InitBlock> {
    info_header(i).and_then(|(i, o)| match o.data_type {
        DataType::Idata => map(pair(be_u8, count(be_u8, o.len)), InitBlock::Idata)(i),
        DataType::Xdata => map(pair(be_u16, count(be_u8, o.len)), InitBlock::Xdata)(i),
        DataType::Pdata => map(pair(be_u8, count(be_u8, o.len)), InitBlock::Pdata)(i),
        DataType::Bit => map(count(bits::bits(bit_init), o.len), InitBlock::Bit)(i),
        DataType::Hdata => map(pair(be_u24, count(be_u8, o.len)), InitBlock::Hdata)(i),
    })
}

/// Contains information pertaining to the initialization data of the
/// data structure that is used to set up the values on startup
/// of a 8051 firmware that is compiled with a Keil C51 compiler.
/// Typically, its address is loaded into dptr right at the beginning
/// of ?C_START, which we can normally find with the libfind subcommand.
#[derive(Debug, PartialEq, Serialize)]
pub struct InitData {
    blocks: Vec<InitBlock>,
}

impl InitData {
    /// reads the init structure (assuming it starts right at the beginning
    /// of i).
    pub fn new(i: &[u8]) -> Result<Self, nom::Err<nom::error::Error<&[u8]>>> {
        map(
            // the structure is 0-terminated, which is encoded into init_block itself
            terminated(many0(init_block), bytes::complete::tag(&[0][..])),
            |blocks| InitData { blocks },
        )(i)
        .map(|x| x.1)
    }
    /// Prints the information of the init structure to stdout.
    pub fn print(&self) {
        for block in &self.blocks {
            let regular_pair;
            let mut line = String::from("");
            match block {
                // for IDATA, XDATA, PDATA and HDATA, we
                // pretty much do the same, but we have to convert
                // the addresses to u32 to unify the printing
                InitBlock::Idata((addr, valvec)) => {
                    line.push_str("idata");
                    regular_pair = Some((u32::from(*addr), valvec));
                }
                InitBlock::Xdata((addr, valvec)) => {
                    line.push_str("xdata");
                    regular_pair = Some((u32::from(*addr), valvec));
                }
                InitBlock::Pdata((addr, valvec)) => {
                    line.push_str("pdata");
                    regular_pair = Some((u32::from(*addr), valvec));
                }
                InitBlock::Hdata((addr, valvec)) => {
                    line.push_str("hdata");
                    regular_pair = Some((*addr, valvec));
                }
                // the BIT case is a bit different, since it doesn't consist of a start address
                // and then of an array of values to write starting from there, but instead
                // for each byte contains both the value and bit address to set (which also
                // has to be formatted differently)
                InitBlock::Bit(weirdvec) => {
                    let mut iter = weirdvec
                        .iter()
                        // bit addresses start at 0x20 and are formatted as xx.y, where xx is the
                        // byte and y is the bit in the byte
                        .map(|(bitval, bitaddr)| {
                            format!(
                                "bit {:02x}.{} = {}",
                                0x20 + bitaddr / 8,
                                bitaddr % 8,
                                bitval
                            )
                        });
                    let first = match iter.next() {
                        Some(x) => x,
                        // just skip this if the length is 0
                        None => continue,
                    };
                    println!(
                        "{}",
                        iter.fold(first, |acc, net| format!("{}, {}", acc, net))
                    );
                    continue;
                }
            }
            match regular_pair {
                Some((addr, valvec)) => {
                    if valvec.is_empty() {
                        // skip this if length is 0
                        continue;
                    }
                    if valvec.len() == 1 {
                        // if we set one value, just write data[x] = y instead of
                        // data[x..x+1] = [y]
                        line.push_str(&format!("[0x{:x}] = 0x{:02x}", addr, valvec[0]));
                        println!("{}", line);
                        continue;
                    }
                    let first = format!("0x{:02x}", valvec[0]);
                    let array_out = valvec
                        .iter()
                        .skip(1)
                        .map(|byte| format!("0x{:02x}", byte))
                        .fold(first, |acc, net| format!("{}, {}", acc, net));
                    line.push_str(&format!(
                        "[0x{:x}..0x{:x}] = [{}]",
                        addr,
                        addr + valvec.len() as u32,
                        array_out
                    ));
                    println!("{}", line);
                }
                None => panic!("Internal logic error"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn info_header_idata() {
        assert_eq!(
            info_header(&[0x07]),
            Ok((
                &[][..],
                InfoHeader {
                    data_type: DataType::Idata,
                    len: 7
                }
            ))
        );
    }
    #[test]
    fn info_header_xdata() {
        assert_eq!(
            info_header(&[0x69, 0x42]),
            Ok((
                &[][..],
                InfoHeader {
                    data_type: DataType::Xdata,
                    len: 0x942
                }
            ))
        );
    }
    #[test]
    fn info_header_hdata() {
        assert_eq!(
            info_header(&[0xff, 0xff]),
            Ok((
                &[][..],
                InfoHeader {
                    data_type: DataType::Hdata,
                    len: 0x1fff
                }
            ))
        );
    }
    #[test]
    fn init_data_test_zero() {
        assert_eq!(InitData::new(&[0x00]), Ok(InitData { blocks: vec![] }));
    }
    #[test]
    fn init_data_test_regular() {
        assert_eq!(
            InitData::new(&hex::decode("47040348454C4C4F210AC14E015A0000").unwrap()),
            Ok(InitData {
                blocks: vec![
                    InitBlock::Xdata((0x403u16, vec![0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x21, 0x0a])),
                    InitBlock::Bit(vec![(0, 0x4e)]),
                    InitBlock::Idata((0x5a, vec![0]))
                ]
            })
        )
    }
}
