//! Module for searching for library segments in a firmware image and outputting the positions of
//! the public symbols in that file.
pub mod aslink3;
pub mod omf51;
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{map, opt},
    sequence::tuple,
    IResult,
};
use serde::Serialize;
use std::{collections::HashMap, convert::TryInto, fs, io::Result};

pub type RefHashMap = HashMap<usize, Vec<(String, RefKind)>>;
/// Reads a list of libraries, parses them and calls the find_segments function on each of them for
/// the function, returning the cslist and rslist arrays.
/// For files in the libpath array, all available parsers are tried and if it does not work, the
/// file is skipped.
/// For directories in the libpath array, all files in the directory are tried.
/// # Arguments
/// * `libpath`: Array of libraray paths
/// * `contents`: Contents of the file to find segments of
/// * `check`: Whether to check if local references are valid
/// * `min_fn_length`: Minimum length of matched functions
pub fn read_libraries(
    libpath: &[String],
    contents: &[u8],
    check: bool,
    min_fn_length: usize,
) -> Result<(Vec<Vec<Pubsymref>>, RefHashMap)> {
    let mut libnames: Vec<std::path::PathBuf> = Vec::new();
    for path in libpath {
        let path_meta = fs::metadata(path)?;
        // read files directly
        if path_meta.is_file() {
            libnames.push(std::path::PathBuf::from(path));
        }
        // for directories, look for each file
        else if path_meta.is_dir() {
            let dir = fs::read_dir(path)?;
            for entry in dir {
                let real_entry = entry?;
                if real_entry.file_type()?.is_file() {
                    libnames.push(real_entry.path())
                }
            }
        }
    }
    let mut pubnames: Vec<Vec<Pubsymref>> = vec![Vec::new(); contents.len()];
    //    let mut refnames: Vec<Vec<String>> = vec![Vec::new(); 0x10000];
    let mut refnames = HashMap::new();
    for libname in libnames {
        let buffer = fs::read(libname)?;
        // try both the omf51 and aslink3 parser
        let parsed = omf51::Omf51Objects::new(&buffer)
            .map(|x| x.try_into())
            .or_else(|_| aslink3::Aslink3Objects::new(&buffer).map(|x| x.try_into()));
        // skip files we are not able to parse
        if parsed.is_err() {
            continue;
        }
        let modseg: SegmentCollection = parsed
            .unwrap()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        modseg.find_segments(contents, &mut pubnames, &mut refnames, check, min_fn_length);
    }
    Ok((pubnames, refnames))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefKind {
    Invalid,
    Valid,
}

/// A single instance of a public symbol found in a firmware image at an address
#[derive(Serialize)]
pub struct Segref {
    location: usize,
    name: String,
    goodness: SymGoodness,
    description: Option<String>,
}

/// Combines cslist and rslist into a vector of Segref and adds description for Keil load, store and
/// arithmetic routines.
///
/// # Arguments
/// * `cslist`: List of public symbols of segments found in the file at each address and the
///   symbols it references
/// * `rslist`: HashMap of public symbols referenced by segments by address
/// * `skip_multiple`: whether to skip addresses with multiple recognized symbols
pub fn process_segrefs(
    cslist: &mut [Vec<Pubsymref>],
    rslist: &mut RefHashMap,
    skip_amount: Option<usize>,
) -> Vec<Segref> {
    // first get all symbols which lay in the file
    let mut segrefs: Vec<Segref> = Vec::new();
    for i in 0..cslist.len() {
        let matches = unify_refs(cslist, rslist, i);
        if let Some(amount) = skip_amount {
            if matches.len() > amount {
                continue;
            }
        }
        for (s, r) in matches {
            segrefs.push(Segref {
                location: i,
                name: String::from(s),
                goodness: r,
                description: None,
            });
        }
    }
    // symbols outside the file can only be by reference and are stored in the hashmap
    let mut leftover_refs: Vec<_> = rslist.iter().filter(|(i, _)| **i >= cslist.len()).collect();
    leftover_refs.sort_by_key(|(i, _)| **i);
    for (i, arr) in leftover_refs.into_iter() {
        if let Some(amount) = skip_amount {
            if arr.len() > amount {
                continue;
            }
        }
        for s in arr.iter().filter(|s| s.1 == RefKind::Valid) {
            segrefs.push(Segref {
                location: *i,
                name: s.0.clone(),
                goodness: SymGoodness::RefOnly,
                description: None,
            });
        }
    }
    for segref in &mut segrefs {
        // add description if regex matches
        if let Ok((_, (_, signed, datatype, (operation, target, addendum)))) =
            parse_description(&segref.name)
        {
            let mut desc = String::from("");
            desc.push_str(match signed {
                Some("S") => "signed ",
                Some("U") => "unsigned ",
                Some(_) => "<unknown sign> ",
                None => "",
            });
            desc.push_str(match datatype {
                "C" => "char (8-bit) ",
                "I" => "int (16-bit) ",
                "P" => "general pointer ",
                "L" => "long (32-bit) ",
                "L0" => "long (r3-r0) ",
                "FP" => "float ",
                _ => "<unknown type> ",
            });
            desc.push_str(match operation {
                "LD" => "load from ",
                "ILD" => "pre-increment load from ",
                "LDI" => "post-increment load from ",
                "ST" => "store to ",
                "STK" => "constant store to ",
                "ADD" => "addition",
                "SUB" => "subtraction",
                "MUL" => "multiply",
                "DIV" => "division",
                "CMP" => "compare",
                "AND" => "bitwise and",
                "OR" => "bitwise or",
                "XOR" => "bitwise xor",
                "NEG" => "negation",
                "NOT" => "logical not",
                "SHL" => "shift left",
                "SHR" => "shift right",
                _ => "<unknown operation>",
            });
            desc.push_str(match target {
                Some("XDATA") => "xdata",
                Some("PDATA") => "pdata (external ram)",
                Some("IDATA") => "idata (indirect ram access)",
                Some("CODE") => "code space",
                Some("OPTR") => "general pointer with offset",
                Some("PTR") => "general pointer",
                None => "",
                _ => "<unknown memory>",
            });
            if addendum.is_some() {
                desc.push_str(" into r3-r0");
            }
            segref.description = Some(desc);
        }
    }
    segrefs
}

// make linter happy
type Operation<'a> = (&'a str, Option<&'a str>, Option<&'a str>);

fn parse_description(i: &str) -> IResult<&str, (&str, Option<&str>, &str, Operation)> {
    tuple((
        tag("?C?"),
        opt(alt((
            // signed
            tag("S"),
            // unsigned
            tag("U"),
        ))),
        alt((tag("C"), tag("I"), tag("P"), tag("L0"), tag("L"), tag("FP"))),
        alt((
            map(
                alt((
                    tag("ADD"),
                    tag("SUB"),
                    tag("MUL"),
                    tag("DIV"),
                    tag("CMP"),
                    tag("AND"),
                    tag("OR"),
                    tag("XOR"),
                    tag("NEG"),
                    tag("NOT"),
                    tag("SHL"),
                    tag("SHR"),
                )),
                |x| (x, None, None),
            ),
            map(
                tuple((
                    alt((tag("LD"), tag("LDI"), tag("ILD"), tag("STK"), tag("ST"))),
                    alt((
                        tag("XDATA"),
                        tag("PDATA"),
                        tag("IDATA"),
                        tag("CODE"),
                        tag("OPTR"),
                        tag("PTR"),
                    )),
                    opt(tag("0")),
                )),
                |(a, b, c)| (a, Some(b), c),
            ),
        )),
    ))(i)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Pubsymref {
    pub name: String,
    valid: bool,
    refs: Vec<(usize, String)>,
}

/// Prints all public symbols found in a table.
/// Symbols which are only found through references (such as main most of the time)
/// are put into parantheses.
pub fn print_segrefs(segrefs: &[Segref]) {
    println!("Address | {:<20} | Description", "Name",);
    for segref in segrefs {
        print!("{:<7} ", format!("0x{:04x}", segref.location));
        // indirect references are inside parens
        if segref.goodness == SymGoodness::RefOnly {
            print!(" {:<22} ", format!("({})", segref.name));
        } else if segref.goodness == SymGoodness::SymWithoutRef {
            print!(" {:<22} ", format!("[{}]", segref.name));
        } else {
            print!(" {:<22} ", format!(" {} ", segref.name));
        }
        match &segref.description {
            Some(des) => println!(" {}", des),
            // empty description
            None => println!(),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Serialize)]
pub enum SymGoodness {
    /// symbol is only a reference made by another segment
    RefOnly = 0,
    /// symbol content is found in bytes, but references don't check out
    SymWithoutRef = 1,
    /// symbol content appears in bytes and references also
    GoodSym = 2,
    /// symbol content appears in bytes and references also, and is referenced by other segments
    ReferencedGoodSym = 3,
}

/// Merges two lists and gives a boolean value for each if the item is only present in the second list.
fn unify_refs<'a>(
    cslist: &'a mut [Vec<Pubsymref>],
    rslist: &'a mut RefHashMap,
    index: usize,
) -> Vec<(&'a str, SymGoodness)> {
    let mut symarray: Vec<(&str, SymGoodness)> = Vec::new();
    // sort both lists so we can simple merge them from left to right
    if let Some(arr) = cslist.get_mut(index) {
        arr.sort();
    }
    if let Some(arr) = rslist.get_mut(&index) {
        arr.sort();
    }
    let a = cslist.get(index).map(|x| x.as_slice()).unwrap_or_default();
    let b = rslist.get(&index).map(|x| x.as_slice()).unwrap_or_default();
    let mut aidx = 0;
    let mut bidx = 0;
    // if both indexes are at the end of their lists, we are finished
    while aidx < a.len() || bidx < b.len() {
        if aidx < a.len() && (bidx >= b.len() || a[aidx].name <= b[bidx].0) {
            let is_reffed = Some(&a[aidx].name) == b.get(bidx).map(|x| &x.0);
            if !is_reffed && !a[aidx].valid {
                aidx += 1;
                continue;
            }
            let mut validrefs = true;
            for (idx, refname) in &a[aidx].refs {
                if let Some(subarr) = cslist.get(*idx) {
                    validrefs = validrefs && subarr.iter().any(|x| &x.name == refname);
                    if !validrefs {
                        break;
                    }
                } else {
                    validrefs = false;
                    break;
                }
            }
            let goodness = if validrefs {
                if is_reffed {
                    SymGoodness::ReferencedGoodSym
                } else {
                    SymGoodness::GoodSym
                }
            } else {
                SymGoodness::SymWithoutRef
            };
            symarray.push((&a[aidx].name, goodness));
            aidx += 1;
        } else if bidx < b.len() && (aidx >= a.len() || a[aidx].name >= b[bidx].0) {
            if b[bidx].1 == RefKind::Valid {
                symarray.push((&b[bidx].0, SymGoodness::RefOnly));
            }
            bidx += 1;
        } else {
            unreachable!()
        };
    }
    // only use symbols with maximum goodness
    let maxel = symarray
        .iter()
        .map(|(_, x)| x)
        .max()
        .unwrap_or(&SymGoodness::RefOnly)
        .clone();
    let mut retarray = Vec::new();
    for (name, good) in symarray.into_iter().filter(|(_, x)| x == &maxel) {
        if retarray.last().map(|(s, _)| s) != Some(&name) {
            retarray.push((name, good));
        }
    }
    retarray
}

/// A collection of segments in general form.
pub struct SegmentCollection {
    segments: Vec<Segment>,
}

impl SegmentCollection {
    /// Create a new SegmentCollection from a vector of Segments
    pub fn new(segments: Vec<Segment>) -> Self {
        Self { segments }
    }
    /// Finds segments defined in this SegmentCollection inside a buffer.
    /// # Arguments
    /// * `self`: collection of segments to find
    /// * `buf`: buffer to find segments in
    /// * `cslist`: vector to add public symbols name of found segments, cslist.len() == buf.len()
    /// * `rslist`: vector to add public symbol references from found segments, rslist.len() ==
    ///   0x10000
    /// * `checkref`: whether to check if local direct segment refernces are checked for validity
    ///   (reduces noise)
    /// * `min_fn_length`: minimum length of a matched function
    pub fn find_segments(
        self,
        buf: &[u8],
        cslist: &mut [Vec<Pubsymref>],
        rslist: &mut RefHashMap,
        checkref: bool,
        min_fn_length: usize,
    ) {
        let mut seglist: Vec<Vec<usize>> = Vec::new();
        // first find all segments in the buffer
        for seg in &self.segments {
            let locs = match seg.segtype {
                // if it is an absolute segment, only search at the actual location
                SegType::Absolute(idx) => {
                    if check_at_location(0, buf, &seg.content_mask, idx) {
                        vec![idx]
                    } else {
                        vec![]
                    }
                }
                // for relocatable segments, search verywhere
                SegType::Relocatable => find_masked_subvalue(0, buf, &seg.content_mask),
            };
            seglist.push(locs);
        }
        for (segment, x) in self.segments.iter().zip(seglist.iter()) {
            for segpos in x {
                // short segments can create a lot of noise and we don't really care for them
                // anyway
                let active_bytes: usize = segment
                    .content_mask
                    .iter()
                    .map(|(_, mask)| usize::from(*mask != 0))
                    .sum();
                let is_active = active_bytes >= min_fn_length;
                let kind = if is_active {
                    RefKind::Valid
                } else {
                    RefKind::Invalid
                };
                let mut invalid = false;
                let mut refvec: Vec<(usize, String)> = Vec::new();
                for fix in &segment.fixup {
                    invalid |= !match (&fix.code_ref.reftype, fix.find_target(buf, *segpos)) {
                        // for direct references, check if the other segment exists
                        (RefType::SegId(id), Some(target)) => seglist[*id].contains(&target),
                        // for public references, just add the name to the rslist
                        (RefType::Pubname(name), Some(target)) => {
                            let entry = rslist.entry(target).or_default();
                            match entry.iter_mut().find(|x| &x.0 == name) {
                                Some((_, ref_kind)) => {
                                    *ref_kind = (*ref_kind).max(kind);
                                }
                                None => {
                                    entry.push((name.clone(), kind));
                                }
                            }
                            refvec.push((target, name.clone()));
                            true
                        }
                        // if the reference lands outside of the addresses of the buffer,
                        // the reference is invalid
                        (_, None) => false,
                    }
                }
                invalid &= checkref;
                if !invalid {
                    for (sym, offset) in &segment.pubsyms {
                        if cslist[segpos + offset].iter().all(|x| &x.name != sym) {
                            cslist[segpos + offset].push(Pubsymref {
                                name: sym.clone(),
                                valid: is_active,
                                refs: refvec.clone(),
                            });
                        }
                    }
                }
            }
        }
    }
}

// to be replaced by suffix tree implementation?
// for 8051 code (which is at most 64k) this seems to be fast enough
fn find_masked_subvalue(whstart: usize, whole: &[u8], subvalue: &[(u8, u8)]) -> Vec<usize> {
    let mut locations = Vec::new();
    // if it is bigger than the whole buffer, it is obviously not contained
    if subvalue.len() > whole.len() {
        return locations;
    }
    // check for each possible position whether it is there
    for i in whstart..=whstart + whole.len() - subvalue.len() {
        if check_at_location(whstart, whole, subvalue, i) {
            locations.push(i);
        }
    }
    locations
}

// checks whether a masked byte array is at a certain location (ignoring bits which are unmasked)
fn check_at_location(whstart: usize, whole: &[u8], subvalue: &[(u8, u8)], start: usize) -> bool {
    // if either side is out of bounds, it is not contained
    if start < whstart || start + subvalue.len() > whstart + whole.len() {
        return false;
    }
    for (i, (c, m)) in subvalue.iter().enumerate() {
        // mask both values by mask and then compare them for equality,
        // which is equivalent to (a^b)&m != 0
        // SIMD?
        if ((whole[start - whstart + i] ^ c) & m) != 0 {
            return false;
        }
    }
    true
}

enum SegType {
    Absolute(usize),
    Relocatable,
}

/// Definition of a single segment extracted from a library file in general form.
pub struct Segment {
    segtype: SegType,
    content_mask: Vec<(u8, u8)>,
    fixup: Vec<Fixup>,
    pubsyms: Vec<(String, usize)>,
}

impl Segment {
    /// New absolute Segment.
    /// # Arguments
    /// * `addr`: Absolute address of the segment
    /// * `content_mask`: (value,mask) pairs of the segment, where fixed-up or undefined locations
    ///    are masked
    /// * `fixup`: Vector of Fixups that lead to other code locations
    /// * `pubsyms`: Strings and offset of public symbols within segment
    pub fn new_absolute(
        addr: usize,
        content_mask: Vec<(u8, u8)>,
        fixup: Vec<Fixup>,
        pubsyms: Vec<(String, usize)>,
    ) -> Self {
        Segment {
            segtype: SegType::Absolute(addr),
            content_mask,
            fixup,
            pubsyms,
        }
    }
    /// New relocatable Segment.
    /// # Arguments
    /// * `content_mask`: (value,mask) pairs of the segment, where fixed-up or undefined locations
    ///    are masked
    /// * `fixup`: Vector of Fixups that lead to other code locations
    /// * `pubsyms`: Strings and offset of public symbols within segment
    pub fn new_relocatable(
        content_mask: Vec<(u8, u8)>,
        fixup: Vec<Fixup>,
        pubsyms: Vec<(String, usize)>,
    ) -> Self {
        Segment {
            segtype: SegType::Relocatable,
            content_mask,
            fixup,
            pubsyms,
        }
    }
}

pub type AddressFunction = Box<dyn Fn(&[u8], usize) -> usize>;

/// A fixup, which is a memory location within a segment which references another memory location
/// and is filled in later by the linker.
pub struct Fixup {
    refloc: usize,
    size: usize,
    addr_fun: AddressFunction,
    code_ref: CodeRef,
}

impl Fixup {
    /// Creates a new Fixup
    ///
    /// # Arguments
    /// * `refloc`: location of fixup relative to segment begin
    /// * `size`: size of the region that is fixed up
    /// * `addr_fun`: a function that, given the bytes and absolute address of the fixup location,
    ///   returns the location pointed to
    /// * `code_ref`: Type of reference (segment or public symbol)
    pub fn new(
        refloc: usize,
        size: usize,
        // kept general in case of ASLINK implementation
        addr_fun: AddressFunction,
        code_ref: CodeRef,
    ) -> Self {
        Fixup {
            refloc,
            size,
            addr_fun,
            code_ref,
        }
    }
    pub fn addr16(refloc: usize, code_ref: CodeRef) -> Self {
        Fixup {
            refloc,
            size: 2,
            addr_fun: Box::new(|bytes, _| {
                (((bytes[0] as usize) << 8) + bytes[1] as usize) & 0xffff
            }),
            code_ref,
        }
    }
    pub fn addr11(refloc: usize, code_ref: CodeRef) -> Self {
        Fixup {
            refloc,
            size: 2,
            addr_fun: Box::new(|bytes, pos| {
                ((pos.wrapping_add(2)) & 0xf800
                    | ((bytes[0] as usize) << 8) & 7
                    | bytes[1] as usize)
                    & 0xffff
            }),
            code_ref,
        }
    }
    pub fn relative(refloc: usize, code_ref: CodeRef) -> Self {
        Fixup {
            refloc,
            size: 1,
            addr_fun: Box::new(|bytes, pos| {
                pos.wrapping_add(1).wrapping_add((bytes[0]) as i8 as usize)
            }),
            code_ref,
        }
    }
    /// Given the bytes and the address, tries to find the location pointed to
    pub fn find_target(&self, buf: &[u8], segpos: usize) -> Option<usize> {
        let actual_position = segpos + self.refloc;
        // if it points outside of the buffer, return None
        if actual_position + self.size > buf.len() {
            return None;
        }
        // invoke the address finding function with the relevant bytes at the location of it
        Some(
            (self.addr_fun)(&buf[actual_position..], actual_position)
                .wrapping_sub(self.code_ref.offset),
        )
    }
}

enum RefType {
    // public name of location
    Pubname(String),
    // segment id, offset
    SegId(usize),
}

pub struct CodeRef {
    reftype: RefType,
    offset: usize,
}

impl CodeRef {
    pub fn new_pubref(name: String, offset: usize) -> CodeRef {
        CodeRef {
            reftype: RefType::Pubname(name),
            offset,
        }
    }
    pub fn new_segid(id: usize, offset: usize) -> CodeRef {
        CodeRef {
            reftype: RefType::SegId(id),
            offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unify_refs_1() {
        let mut ref_hashmap = HashMap::new();
        ref_hashmap.insert(
            0,
            vec![
                (String::from("a"), RefKind::Invalid),
                (String::from("b"), RefKind::Valid),
            ],
        );
        assert_eq!(
            unify_refs(&mut vec![][..], &mut ref_hashmap, 0),
            vec![("b", SymGoodness::RefOnly)]
        );
    }
    #[test]
    fn unify_refs_2() {
        let mut ref_hashmap = HashMap::new();
        ref_hashmap.insert(
            0,
            vec![
                (String::from("ba"), RefKind::Valid),
                (String::from("c"), RefKind::Valid),
            ],
        );
        assert_eq!(
            unify_refs(
                &mut vec![vec![
                    Pubsymref {
                        name: String::from("c"),
                        valid: true,
                        refs: vec![(4, String::from("k"))]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        valid: true,
                        refs: vec![(7, String::from("l"))]
                    },
                    Pubsymref {
                        name: String::from("d"),
                        valid: false,
                        refs: vec![(0, String::from("c"))]
                    }
                ]][..],
                &mut ref_hashmap,
                0
            ),
            vec![
                ("ab", SymGoodness::SymWithoutRef),
                ("c", SymGoodness::SymWithoutRef)
            ]
        );
    }
    #[test]
    fn unify_refs_3() {
        let mut ref_hashmap = HashMap::new();
        ref_hashmap.insert(
            0,
            vec![
                (String::from("ba"), RefKind::Valid),
                (String::from("c"), RefKind::Invalid),
            ],
        );
        assert_eq!(
            unify_refs(
                &mut vec![vec![
                    Pubsymref {
                        name: String::from("c"),
                        valid: true,
                        refs: vec![(4, String::from("k"))]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        valid: true,
                        refs: vec![(3, String::from("k")), (7, String::from("l"))]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        valid: true,
                        refs: vec![(0, String::from("c"))]
                    }
                ]][..],
                &mut ref_hashmap,
                0
            ),
            vec![("ab", SymGoodness::GoodSym),]
        );
    }
    #[test]
    fn unify_refs_4() {
        let mut ref_hashmap = HashMap::new();
        ref_hashmap.insert(
            0,
            vec![
                (String::from("ab"), RefKind::Valid),
                (String::from("c"), RefKind::Valid),
            ],
        );
        assert_eq!(
            unify_refs(
                &mut vec![vec![
                    Pubsymref {
                        name: String::from("b"),
                        valid: true,
                        refs: vec![]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        valid: true,
                        refs: vec![]
                    },
                ]][..],
                &mut ref_hashmap,
                0
            ),
            vec![("ab", SymGoodness::ReferencedGoodSym),]
        );
    }
    #[test]
    fn find_masked_subvalue_oversize() {
        let empty: Vec<usize> = vec![];
        assert_eq!(
            find_masked_subvalue(
                0,
                &[0, 1, 1, 2, 3, 5, 8],
                &[
                    (0, 0xff),
                    (1, 0xff),
                    (1, 0xff),
                    (2, 0xff),
                    (3, 0xff),
                    (5, 0xff),
                    (8, 0xff),
                    (13, 0xff)
                ]
            ),
            empty
        );
    }
    #[test]
    fn find_masked_subvalue_offset() {
        assert_eq!(
            find_masked_subvalue(
                0x15,
                &[0x33, 0x64, 0x86, 0x53, 0xf1, 0x86, 0x53],
                &[(0x13, 0x1f), (0, 0), (0x86, 0xff), (0x53, 0xff)]
            ),
            vec![0x15, 0x18]
        );
    }
    #[test]
    fn check_at_location_end() {
        assert!(check_at_location(
            0x10,
            &[0x10, 0x11, 0x12, 0x13],
            &[(0x91, 0x7f), (0x12, 0xfe), (0x13, 0x13)],
            0x11
        ));
    }
}
