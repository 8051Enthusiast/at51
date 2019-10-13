//! Module for parsing OMF51 files (you know, the totally well-known format which was specified by
//! Intel in the early 80s, so you know it has to be good).
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{complete, map, rest, verify},
    error::ErrorKind,
    multi::{length_data, length_value, many0, many1},
    number::complete::{le_u16, le_u8},
    sequence::{delimited, pair, preceded, terminated, tuple},
    IResult,
};
use num_traits::FromPrimitive;

static KNOWN_TYPES: [u8; 21] = [
    0x02, 0x04, 0x06, 0x07, 0x08, 0x08, 0x09, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x18,
    0x19, 0x26, 0x28, 0x2a, 0x2c,
];

// strings in OMF51 are saved as a byte specifying the length followed by the text
fn lenstr(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    length_data(le_u8)(i).map(|(i, x)| (i, x.to_vec()))
}

// the content of a module header record is a string followed by a id of the generating program, which we
// don't reall need
fn header(i: &[u8]) -> IResult<&[u8], (Vec<u8>, u8)> {
    pair(lenstr, terminated(le_u8, le_u8))(i)
}

// the content of a module end record, containing the module name again and a register mask (for
// which we don't really care)
fn endmod(i: &[u8]) -> IResult<&[u8], (Vec<u8>, u8)> {
    pair(terminated(lenstr, le_u16), terminated(le_u8, le_u8))(i)
}

#[derive(Debug, PartialEq)]
enum Definition {
    Segment(SegmentDef),
    Public(PublicDef),
    Extern(ExternDef),
}

// address spaces the segments can reside in
#[derive(Debug, PartialEq)]
enum SegTyp {
    Code = 0,
    Xdata = 1,
    Data = 2,
    Idata = 3,
    Bit = 4,
}
impl FromPrimitive for SegTyp {
    fn from_i64(n: i64) -> Option<Self> {
        match n {
            0 => Some(SegTyp::Code),
            1 => Some(SegTyp::Xdata),
            2 => Some(SegTyp::Data),
            3 => Some(SegTyp::Idata),
            4 => Some(SegTyp::Bit),
            _ => None
        }
    }
    fn from_u64(n: u64) -> Option<Self> {
        match n {
            0 => Some(SegTyp::Code),
            1 => Some(SegTyp::Xdata),
            2 => Some(SegTyp::Data),
            3 => Some(SegTyp::Idata),
            4 => Some(SegTyp::Bit),
            _ => None
        }
    }
}

// type of relocation of segment
#[derive(Debug, PartialEq)]
enum RelTyp {
    Abs = 0,
    Unit = 1,
    Bitaddressable = 2,
    Inpage = 3,
    Inblock = 4,
    Page = 5,
}
impl FromPrimitive for RelTyp {
    fn from_i64(n: i64) -> Option<Self> {
        match n {
            0 => Some(RelTyp::Abs),
            1 => Some(RelTyp::Unit),
            2 => Some(RelTyp::Bitaddressable),
            3 => Some(RelTyp::Inpage),
            4 => Some(RelTyp::Inblock),
            5 => Some(RelTyp::Page),
            _ => None
        }
    }
    fn from_u64(n: u64) -> Option<Self> {
        match n {
            0 => Some(RelTyp::Abs),
            1 => Some(RelTyp::Unit),
            2 => Some(RelTyp::Bitaddressable),
            3 => Some(RelTyp::Inpage),
            4 => Some(RelTyp::Inblock),
            5 => Some(RelTyp::Page),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq)]
struct SegmentDef {
    id: u16,
    segtyp: Option<SegTyp>,
    reltyp: Option<RelTyp>,
    base: usize,
    size: usize,
    name: Vec<u8>,
}

// the Keil people extended the segid field in their implementation,
// adding the corresponding records in the odd type indexes
fn segid(longm: bool) -> impl Fn(&[u8]) -> IResult<&[u8], u16> {
    move |i| {
        if longm {
            le_u16(i)
        } else {
            map(le_u8, u16::from)(i)
        }
    }
}

// a definition of a segment, which doesn't contain the content yet but
// just some definition on relocatability and space requirements
fn segdef(longm: bool) -> impl Fn(&[u8]) -> IResult<&[u8], Definition> {
    move |i| {
        let (i, (id, info, reltyp, base, size, name)) = tuple((
            segid(longm),
            le_u8,
            terminated(le_u8, le_u8),
            le_u16,
            le_u16,
            lenstr,
        ))(i)?;
        let segtyp = FromPrimitive::from_u8(info & 0x7);
        let reltyp = FromPrimitive::from_u8(reltyp);
        let size = if 0x80 == (info & 0x80) {
            0
        } else if size == 0 {
            0x10000
        } else {
            size as usize
        };
        Ok((
            i,
            Definition::Segment(SegmentDef {
                id,
                segtyp,
                reltyp,
                base: base as usize,
                size,
                name,
            }),
        ))
    }
}

#[derive(Debug, PartialEq)]
struct PublicDef {
    id: u16,
    segtyp: Option<SegTyp>,
    offset: usize,
    name: Vec<u8>,
}

// a definition of a public symbol that resides in a segment in this module
fn pubdef(longm: bool) -> impl Fn(&[u8]) -> IResult<&[u8], Definition> {
    move |i| {
        let to_pubdefstr = |(id, segtyp, offset, name)| {
            Definition::Public(PublicDef {
                id,
                segtyp,
                offset,
                name,
            })
        };
        map(
            tuple((
                segid(longm),
                map(le_u8, |x| FromPrimitive::from_u8(x & 0x7)),
                terminated(map(le_u16, |x| x as usize), le_u8),
                lenstr,
            )),
            to_pubdefstr,
        )(i)
    }
}

#[derive(Debug, PartialEq)]
struct ExternDef {
    id_blk: u8,
    ext_id: u16,
    segtyp: Option<SegTyp>,
    name: Vec<u8>,
}

// a reference to a public symbol residing externally so that it can be referenced internally by an
// id
fn extdef(longm: bool) -> impl Fn(&[u8]) -> IResult<&[u8], Definition> {
    move |i| {
        let to_extdefstr = |(id_blk, ext_id, segtyp, name)| {
            Definition::Extern(ExternDef {
                id_blk,
                ext_id,
                segtyp,
                name,
            })
        };
        map(
            tuple((
                le_u8,
                segid(longm),
                terminated(map(le_u8, |x| FromPrimitive::from_u8(x & 0x7)), le_u8),
                lenstr,
            )),
            to_extdefstr,
        )(i)
    }
}

#[derive(Debug, PartialEq)]
struct Content {
    id: u16,
    offset: usize,
    data: Vec<u8>,
}

// the content to add to a segment (the actual bytes)
fn content(longm: bool) -> impl Fn(&[u8]) -> IResult<&[u8], Content> {
    move |i| {
        let to_content = |(id, offset, data)| Content { id, offset, data };
        map(
            tuple((
                segid(longm),
                map(le_u16, |x| x as usize),
                map(rest, |x: &[u8]| x.to_vec()),
            )),
            to_content,
        )(i)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum RefTyp {
    Low = 0,
    Byte = 1,
    Relative = 2,
    High = 3,
    Word = 4,
    Inblock = 5,
    BitAddr = 6,
    Conv = 7,
}
impl FromPrimitive for RefTyp {
    fn from_i64(n: i64) -> Option<Self> {
        match n {
            0 => Some(RefTyp::Low),
            1 => Some(RefTyp::Byte),
            2 => Some(RefTyp::Relative),
            3 => Some(RefTyp::High),
            4 => Some(RefTyp::Word),
            5 => Some(RefTyp::Inblock),
            6 => Some(RefTyp::BitAddr),
            7 => Some(RefTyp::Conv),
            _ => None
        }
    }
    fn from_u64(n: u64) -> Option<Self> {
        match n {
            0 => Some(RefTyp::Low),
            1 => Some(RefTyp::Byte),
            2 => Some(RefTyp::Relative),
            3 => Some(RefTyp::High),
            4 => Some(RefTyp::Word),
            5 => Some(RefTyp::Inblock),
            6 => Some(RefTyp::BitAddr),
            7 => Some(RefTyp::Conv),
            _ => None
        }
    }
}

#[derive(Debug, PartialEq)]
struct Fixup {
    refloc: usize,
    reftyp: Option<RefTyp>,
    id_blk: u8,
    id: u16,
    offset: usize,
}

// content records are sometimes followed by a list of fixups, which
// specify how to fill in addresses later by the linker for addresses
// that aren't known beforehand
fn fixup(longm: bool) -> impl Fn(&[u8]) -> IResult<&[u8], Fixup> {
    move |i| {
        let to_fixup = |(refloc, reftyp, id_blk, id, offset)| Fixup {
            refloc,
            reftyp,
            id_blk,
            id,
            offset,
        };
        map(
            tuple((
                map(le_u16, |x| x as usize),
                map(le_u8, FromPrimitive::from_u8),
                le_u8,
                segid(longm),
                map(le_u16, |x| x as usize),
            )),
            to_fixup,
        )(i)
        .and_then(|(i, o)| {
            if o.id_blk == 3 {
                map(le_u8, |_| Fixup { id_blk: 3, ..o })(i)
            } else {
                Ok((i, o))
            }
        })
    }
}

// each record starts with a record type and the length and ends with a checksum,
// and the inner content can then be parsed by the respective parser
fn record<T, U>(typ: u8, inner: T) -> impl Fn(&[u8]) -> IResult<&[u8], U>
where
    T: Fn(&[u8]) -> IResult<&[u8], U>,
{
    move |i| {
        terminated(
            preceded(tag(&[typ]), length_value(map(le_u16, |x| x - 1), &inner)),
            le_u8,
        )(i)
    }
}

// often, a record can contain a structure multiple times, which we don't want
// to repeat everytime
fn multi_record<T, U>(typ: u8, inner: T) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<U>>
where
    T: Fn(&[u8]) -> IResult<&[u8], U>,
{
    move |i| {
        terminated(
            preceded(
                tag(&[typ]),
                length_value(map(le_u16, |x| x - 1), many1(complete(&inner))),
            ),
            le_u8,
        )(i)
    }
}

// a placeholder for unknown records/records we don't care about
fn placeholder_record<T>(
    pred: impl Fn(&u8) -> bool,
) -> impl Fn(&[u8]) -> IResult<&[u8], Option<T>> {
    move |i| {
        map(
            tuple((
                verify(le_u8, &pred),
                length_data(map(le_u16, |x| x - 1)),
                le_u8,
            )),
            |_| None,
        )(i)
    }
}

// a placeholder with a specific type
fn placeholder_typ_record(typ: u8) -> impl Fn(&[u8]) -> IResult<&[u8], ()> {
    move |i| map(placeholder_record(|x| x == &typ), |_: Option<()>| ())(i)
}

// definition records are grouped together
fn def_records(i: &[u8]) -> IResult<&[u8], Vec<Definition>> {
    map(
        many0(alt((
            map(
                alt((
                    multi_record(0x0e, segdef(false)),
                    multi_record(0x0f, segdef(true)),
                    multi_record(0x16, pubdef(false)),
                    multi_record(0x17, pubdef(true)),
                    multi_record(0x18, extdef(false)),
                    multi_record(0x19, extdef(true)),
                )),
                Some,
            ),
            placeholder_record(|x| !KNOWN_TYPES.contains(x)),
        ))),
        // turns Vec<Option<Vec<Definition>>> into Vec<Definition>
        |x| x.into_iter().flatten().flatten().collect(),
    )(i)
}

// content and fixup records are also grouped together
fn data_section(i: &[u8]) -> IResult<&[u8], (Content, Vec<Fixup>)> {
    tuple((
        alt((record(0x06, content(false)), record(0x07, content(true)))),
        map(
            many0(alt((
                multi_record(0x08, fixup(false)),
                multi_record(0x09, fixup(true)),
            ))),
            |x| x.into_iter().flatten().collect(),
        ),
    ))(i)
}

// we don't really care for debug records, since they're usually not included in the shipped
// libraries and the ones included don't contain interseting information
fn data_debug_section(i: &[u8]) -> IResult<&[u8], Vec<(Content, Vec<Fixup>)>> {
    map(
        many0(alt((
            map(data_section, Some),
            placeholder_record(|x| !KNOWN_TYPES.contains(x) || [0x10, 0x12, 0x13].contains(x)),
        ))),
        |x| x.into_iter().flatten().collect(),
    )(i)
}

#[derive(Debug)]
struct Module {
    name: Vec<u8>,
    segdefs: Vec<SegmentDef>,
    extdefs: Vec<ExternDef>,
    pubdefs: Vec<PublicDef>,
    content: Vec<(Content, Vec<Fixup>)>,
}

// parser for a whole module
fn module(i: &[u8]) -> IResult<&[u8], Module> {
    map(
        tuple((
            record(0x02, header),
            def_records,
            data_debug_section,
            record(0x04, endmod),
        )),
        |(beg, defs, data, end)| {
            let mut segdefs: Vec<SegmentDef> = vec![];
            let mut extdefs: Vec<ExternDef> = vec![];
            let mut pubdefs: Vec<PublicDef> = vec![];
            for i in defs.into_iter() {
                match i {
                    Definition::Segment(segdef) => segdefs.push(segdef),
                    Definition::Extern(extdef) => extdefs.push(extdef),
                    Definition::Public(pubdef) => pubdefs.push(pubdef),
                }
            }
            assert_eq!(beg.0, end.0);
            Module {
                name: beg.0,
                segdefs,
                extdefs,
                pubdefs,
                content: data,
            }
        },
    )(i)
}

// an object file is either a library or a collection of modules, which is the same as a library
// without all the lookup tables
fn object_file(i: &[u8]) -> IResult<&[u8], Vec<Module>> {
    complete(alt((
        many1(module),
        delimited(
            placeholder_typ_record(0x2c),
            many1(module),
            tuple((
                placeholder_typ_record(0x28),
                placeholder_typ_record(0x26),
                placeholder_typ_record(0x2a),
            )),
        ),
    )))(i)
}

#[derive(Debug)]
pub struct Omf51Objects {
    module: Vec<Module>,
}

impl Omf51Objects {
    pub fn new(stream: &[u8]) -> Result<Self, nom::Err<(&[u8], ErrorKind)>> {
        object_file(stream).map(|x| Omf51Objects { module: x.1 })
    }
}

type Cmf = (Vec<(u8, u8)>, Vec<super::Fixup>);
// a helper function which is responsible for masking content in a segment if a fixup clobbers
// specific bytes or the region is not covered by any content record
fn content_mask_fixup_helper(
    con: &Content,
    fixlist: &[Fixup],
    extlist: &[ExternDef],
    seglist: &[SegmentDef],
    segmap: &[(u16, usize)],
    segment_start: usize,
) -> Result<Cmf, &'static str> {
    let mut fixups: Vec<super::Fixup> = Vec::new();
    // add the mask value 0xff to the whole data since it is valid
    let mut content_mask: Vec<(u8, u8)> = con
        .data
        .clone()
        .into_iter()
        .zip(vec![0xff as u8; con.data.len()].into_iter().cycle())
        .collect();
    for fix in fixlist {
        // experience has shown that id_blk 3 generated by some keil utils is mostly irrelevant and
        // should be ignored in every way possible
        if fix.id_blk == 3 {
            continue;
        }
        match &fix.reftyp {
            // for word fixups, unmask the two whole bytes used
            Some(RefTyp::Word) => {
                if fix.refloc < content_mask.len() {
                    content_mask[fix.refloc].1 = 0;
                }
                if fix.refloc + 1 < content_mask.len() {
                    content_mask[fix.refloc + 1].1 = 0;
                }
            }
            // for inblock fixup, unmask the bytes which are the reference inside of a ajmp/acall
            Some(RefTyp::Inblock) => {
                if fix.refloc < content_mask.len() {
                    content_mask[fix.refloc].1 = 0x1f;
                }
                if fix.refloc + 1 < content_mask.len() {
                    content_mask[fix.refloc + 1].1 = 0;
                }
            }
            // every other reference type covers exactly one byte, which is unmasked here
            Some(_) => {
                if fix.refloc < content_mask.len() {
                    content_mask[fix.refloc].1 = 0;
                }
            }
            _ => return Err("Error: unknown reference type"),
        }
        match fix.id_blk {
            // id_blk 0 is rarely a jump to code and I'm too lazy to implement it
            0 => continue,
            1 => {
                // if it doesn't reference a code segment, skip
                if seglist.iter().find(|x| x.id == fix.id).map(|x| &x.segtyp)
                    != Some(&Some(SegTyp::Code))
                {
                    continue;
                }
            }
            2 => {
                // also if it doesn't reference a code segment, skip
                if extlist
                    .iter()
                    .find(|x| x.ext_id == fix.id)
                    .map(|x| &x.segtyp)
                    != Some(&Some(SegTyp::Code))
                {
                    continue;
                }
            }
            _ => {
                return Err("Error: Unknown id_blk");
            }
        }
        // calculate the CodeRef that corresponds to this fixup
        let new_reftyp = match fix.id_blk {
            1 => {
                // for a segment reference, we just get the id and offset
                let unique_id = segmap.iter().find(|(x, _)| *x == fix.id).unwrap().1;
                super::CodeRef::new_segid(unique_id, fix.offset)
            }
            2 => {
                // for a extern reference, we search for the string and the offset
                let name = match extlist.iter().find(|x| x.ext_id == fix.id).map(|x| &x.name) {
                    Some(stst) => String::from_utf8_lossy(&stst),
                    None => return Err("Reference to non-existent name"),
                };
                super::CodeRef::new_pubref(name.clone().to_string(), fix.offset)
            }
            _ => return Err("Error: unknown ID block"),
        };
        // add the finished fixup records to the vector
        match &fix.reftyp {
            Some(RefTyp::Relative) => {
                fixups.push(super::Fixup::relative(
                    segment_start.wrapping_add(fix.refloc),
                    new_reftyp,
                ));
            }
            Some(RefTyp::Inblock) => {
                fixups.push(super::Fixup::addr11(
                    segment_start.wrapping_add(fix.refloc),
                    new_reftyp,
                ));
            }
            Some(RefTyp::Word) => {
                fixups.push(super::Fixup::addr16(
                    segment_start.wrapping_add(fix.refloc),
                    new_reftyp,
                ));
            }
            Some(_) => (),
            _ => return Err("Error: unknown reference type!"),
        };
    }
    Ok((content_mask, fixups))
}

// merges a new content with mask and offset into a segment with masked content
fn merge_cmf(existent: &mut Cmf, new: &mut Cmf, offset: usize) -> Result<(), &'static str> {
    if offset + new.0.len() > existent.0.len() {
        return Err("Error: Content outside of segment boundaries");
    }
    for (i, x) in new.0.iter().enumerate() {
        existent.0[i + offset].0 |= x.0;
        existent.0[i + offset].1 |= x.1;
    }
    existent.1.append(&mut new.1);
    Ok(())
}

// convert the parsed omf51 file into the format required by the segment finder
impl std::convert::TryFrom<Omf51Objects> for super::SegmentCollection {
    type Error = &'static str;
    fn try_from(mods: Omf51Objects) -> Result<Self, Self::Error> {
        let mut module_array: Vec<super::Segment> = Vec::new();
        // we pretty much discard the information of which segment belongs to which module
        for m in mods.module {
            // get all code segments we need to include so that we can reserve some ids for them
            let relevant_reloc_code_segs: Vec<&SegmentDef> = m
                .segdefs
                .iter()
                .filter(|x| {
                    x.id != 0 && x.reltyp != Some(RelTyp::Abs) && x.segtyp == Some(SegTyp::Code)
                })
                .collect();
            // a map that maps the segment id of the module into a per-file unique segment id
            // so that we don't have to keep track of the module, which we don't need
            let mut segid_unique_map = Vec::new();
            // content & mask & fixup for each segment
            let mut segid_cont_mask = Vec::new();
            for (i, s) in relevant_reloc_code_segs.iter().enumerate() {
                // sequentially allocate ids so that they correspond to position in module_array
                // (which should've been named segment_array)
                segid_unique_map.push((s.id, module_array.len() + i));
                // begin with everything undefined
                let content_mask = vec![(0, 0); s.size];
                let fixups: Vec<super::Fixup> = Vec::new();
                segid_cont_mask.push((content_mask, fixups))
            }
            // for each content record with its fixup, merge the content and mask into the segment
            for (con, fix) in &m.content {
                let mut new_cmf = content_mask_fixup_helper(
                    con,
                    fix,
                    &m.extdefs,
                    &m.segdefs,
                    &segid_unique_map,
                    con.offset,
                )?;
                if let Some(idx) = relevant_reloc_code_segs.iter().position(|x| x.id == con.id) {
                    merge_cmf(&mut segid_cont_mask[idx], &mut new_cmf, con.offset)?;
                }
            }
            // add all public symbols found in these segments and add the finished segments to the
            // array
            for (seg, cmf) in relevant_reloc_code_segs
                .iter()
                .zip(segid_cont_mask.into_iter())
            {
                let pubsyms: Vec<(String, usize)> = m
                    .pubdefs
                    .iter()
                    .filter(|x| x.id == seg.id)
                    .map(|x| {
                        (
                            String::from_utf8_lossy(&x.name).clone().to_string(),
                            x.offset,
                        )
                    })
                    .collect();
                module_array.push(super::Segment::new_relocatable(cmf.0, cmf.1, pubsyms));
            }
            // now collect all absolute segments (or rather, contents, since absolute segments are not
            // associated with the content and we care only for the content)
            for (con, fix) in m.content.iter().filter(|(x, _)| x.id == 0) {
                let cmf = content_mask_fixup_helper(
                    con,
                    fix,
                    &m.extdefs,
                    &m.segdefs,
                    &segid_unique_map,
                    0,
                )?;
                // collect all absolute public symbols which lay within the range of the absolute
                // content descriptor
                let pubsyms_range: Vec<(String, usize)> = m
                    .pubdefs
                    .iter()
                    .filter(|x| {
                        x.id == 0
                            && con.offset <= x.offset
                            && x.offset < con.offset + con.data.len()
                    })
                    .map(|x| {
                        (
                            // theoretically, everything should be ascii, but who follows
                            // specifications anyway
                            String::from_utf8_lossy(&x.name).clone().to_string(),
                            x.offset,
                        )
                    })
                    .collect();
                // add the finished absolute segment
                module_array.push(super::Segment::new_absolute(
                    con.offset,
                    cmf.0,
                    cmf.1,
                    pubsyms_range,
                ));
            }
        }
        Ok(super::SegmentCollection::new(module_array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn parse_lenstr() {
        assert_eq!(
            lenstr(&hex::decode("0b48656c6c6f5f576f726c6415").unwrap()),
            Ok((&[0x15][..], b"Hello_World".to_vec()))
        );
    }
    #[test]
    fn parse_header() {
        assert_eq!(
            header(&hex::decode("134136345f54455354494e475f4c494252415259fd00").unwrap()),
            Ok((&[][..], (b"A64_TESTING_LIBRARY".to_vec(), 0xfd)))
        );
    }
    #[test]
    fn parse_endmod() {
        assert_eq!(
            endmod(&hex::decode("134136345f54455354494e475f4c49425241525900000100").unwrap()),
            Ok((&[][..], (b"A64_TESTING_LIBRARY".to_vec(), 1)))
        );
    }
    #[test]
    fn parse_segdef_1() {
        assert_eq!(
            segdef(true)(&hex::decode("020003010000000100063f535441434b").unwrap()),
            Ok((
                &[][..],
                Definition::Segment(SegmentDef {
                    id: 2,
                    segtyp: Some(SegTyp::Idata),
                    reltyp: Some(RelTyp::Unit),
                    base: 0,
                    size: 1,
                    name: b"?STACK".to_vec()
                })
            ))
        );
    }
    #[test]
    fn parse_segdef_2() {
        assert_eq!(
            segdef(false)(&hex::decode("000000000000030000").unwrap()),
            Ok((
                &[][..],
                Definition::Segment(SegmentDef {
                    id: 0,
                    segtyp: Some(SegTyp::Code),
                    reltyp: Some(RelTyp::Abs),
                    base: 0,
                    size: 3,
                    name: b"".to_vec()
                })
            ))
        );
    }
    #[test]
    fn parse_pubdef_1() {
        assert_eq!(
            pubdef(false)(&hex::decode("0100000000064d4f56584430").unwrap()),
            Ok((
                &[][..],
                Definition::Public(PublicDef {
                    id: 1,
                    segtyp: Some(SegTyp::Code),
                    offset: 0,
                    name: b"MOVXD0".to_vec()
                })
            ))
        );
    }
    #[test]
    fn parse_pubdef_2() {
        assert_eq!(
            pubdef(false)(&hex::decode("01020000000c3f5345545744313f42595445").unwrap()),
            Ok((
                &[][..],
                Definition::Public(PublicDef {
                    id: 1,
                    segtyp: Some(SegTyp::Data),
                    offset: 0,
                    name: b"?SETWD1?BYTE".to_vec()
                })
            ))
        );
    }
    #[test]
    fn parse_extdef_1() {
        assert_eq!(
            extdef(true)(&hex::decode("0201000200063f433f4d4430").unwrap()),
            Ok((
                &[][..],
                Definition::Extern(ExternDef {
                    id_blk: 2,
                    ext_id: 1,
                    segtyp: Some(SegTyp::Data),
                    name: b"?C?MD0".to_vec()
                })
            ))
        );
    }
    #[test]
    fn parse_content() {
        assert_eq!(
            content(true)(&hex::decode("00000000020000").unwrap()),
            Ok((
                &[][..],
                Content {
                    id: 0,
                    offset: 0,
                    data: [0x02, 0x00, 0x00].to_vec()
                }
            ))
        );
    }
    #[test]
    fn parse_fixup() {
        assert_eq!(
            fixup(false)(&hex::decode("0a000402000000").unwrap()),
            Ok((
                &[][..],
                Fixup {
                    refloc: 10,
                    reftyp: Some(RefTyp::Word),
                    id_blk: 2,
                    id: 0,
                    offset: 0
                }
            ))
        );
    }
    #[test]
    fn parse_record() {
        assert_eq!(
            record(0x02, header)(
                &hex::decode("021700134136345f54455354494e475f4c494252415259fd0000").unwrap()
            ),
            header(&hex::decode("134136345f54455354494e475f4c494252415259fd00").unwrap())
        )
    }
    #[test]
    fn parse_multi_record() {
        assert_eq!(
            multi_record(0x16, pubdef(false))(
                &hex::decode(
                    "161f000100000000064d4f5658443001020000000c3f5345545744313f4259544500"
                )
                .unwrap()
            ),
            Ok((
                &[][..],
                vec![
                    pubdef(false)(&hex::decode("0100000000064d4f56584430").unwrap())
                        .unwrap()
                        .1,
                    pubdef(false)(&hex::decode("01020000000c3f5345545744313f42595445").unwrap())
                        .unwrap()
                        .1
                ]
            ))
        );
    }
    #[test]
    fn parse_placeholder_typ_record() {
        assert_eq!(
            placeholder_typ_record(0x2c)(&hex::decode("2c0700080011006d0047").unwrap()),
            Ok((&[][..], ()))
        );
    }
}
