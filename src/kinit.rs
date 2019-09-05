//! Module for reading the initialization structure found on many
//! firmware images compiled with the Keil C51 compiler.
use nom::{
    bits,
    branch::alt,
    bytes,
    combinator::{map, verify},
    error::ErrorKind,
    multi::{count, many0},
    number::complete::{be_u16, be_u24, be_u8},
    sequence::{pair, terminated, tuple},
    IResult,
};

#[derive(Debug, PartialEq)]
enum DataType {
    IDATA,
    XDATA,
    PDATA,
    BIT,
    HDATA,
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
                (0, _) => DataType::IDATA,
                (1, _) => DataType::XDATA,
                (2, _) => DataType::PDATA,
                (3, 0) => DataType::BIT,
                // if BIG BIT is set and the data_type is set as BIT, it is actually HDATA
                (3, 1) => DataType::HDATA,
                // this shouldn't happen because the value is only 2 bits wide
                _ => panic!("A number that shouldn't be out of range is out of range"),
            },
            len: len as usize,
        },
    )(i)
}

#[derive(Debug, PartialEq)]
enum InitBlock {
    IDATA((u8, Vec<u8>)),
    XDATA((u16, Vec<u8>)),
    PDATA((u8, Vec<u8>)),
    BIT(Vec<(u8, u8)>),
    HDATA((u32, Vec<u8>)),
}

// for bits, the value is stored in the 7th bit and the rest in the lower 7 bits
fn bit_init(i: (&[u8], usize)) -> IResult<(&[u8], usize), (u8, u8)> {
    pair(bits::complete::take(1u8), bits::complete::take(7u8))(i)
}

fn init_block(i: &[u8]) -> IResult<&[u8], InitBlock> {
    info_header(i).and_then(|(i, o)| match o.data_type {
        DataType::IDATA => map(pair(be_u8, count(be_u8, o.len)), InitBlock::IDATA)(i),
        DataType::XDATA => map(pair(be_u16, count(be_u8, o.len)), InitBlock::XDATA)(i),
        DataType::PDATA => map(pair(be_u8, count(be_u8, o.len)), InitBlock::PDATA)(i),
        DataType::BIT => map(count(bits::bits(bit_init), o.len), InitBlock::BIT)(i),
        DataType::HDATA => map(pair(be_u24, count(be_u8, o.len)), InitBlock::HDATA)(i),
    })
}

/// Contains information pertaining to the initialization data of the
/// data structure that is used to set up the values on startup
/// of a 8051 firmware that is compiled with a Keil C51 compiler.
/// Typically, its address is loaded into dptr right at the beginning
/// of ?C_START, which we can normally find with the libfind subcommand.
#[derive(Debug, PartialEq)]
pub struct InitData {
    blocks: Vec<InitBlock>,
}

impl InitData {
    /// reads the init structure (assuming it starts right at the beginning
    /// of i).
    pub fn new(i: &[u8]) -> Result<Self, nom::Err<(&[u8], ErrorKind)>> {
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
                InitBlock::IDATA((addr, valvec)) => {
                    line.push_str("idata");
                    regular_pair = Some((u32::from(*addr), valvec));
                }
                InitBlock::XDATA((addr, valvec)) => {
                    line.push_str("xdata");
                    regular_pair = Some((u32::from(*addr), valvec));
                }
                InitBlock::PDATA((addr, valvec)) => {
                    line.push_str("pdata");
                    regular_pair = Some((u32::from(*addr), valvec));
                }
                InitBlock::HDATA((addr, valvec)) => {
                    line.push_str("hdata");
                    regular_pair = Some((*addr, valvec));
                }
                // the BIT case is a bit different, since it doesn't consist of a start address
                // and then of an array of values to write starting from there, but instead
                // for each byte contains both the value and bit address to set (which also
                // has to be formatted differently)
                InitBlock::BIT(weirdvec) => {
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
    use hex;
    #[test]
    fn info_header_idata() {
        assert_eq!(
            info_header(&[0x07]),
            Ok((
                &[][..],
                InfoHeader {
                    data_type: DataType::IDATA,
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
                    data_type: DataType::XDATA,
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
                    data_type: DataType::HDATA,
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
                    InitBlock::XDATA((0x403u16, vec![0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x21, 0x0a])),
                    InitBlock::BIT(vec![(0, 0x4e)]),
                    InitBlock::IDATA((0x5a, vec![0]))
                ]
            })
        )
    }
}
