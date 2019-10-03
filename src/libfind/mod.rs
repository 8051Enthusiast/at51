//! Module for searching for library segments in a firmware image and outputting the positions of
//! the public symbols in that file.
pub mod omf51;
use lazy_static::lazy_static;
use regex::Regex;

/// A single instance of a public symbol found in a firmware image at an address
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
/// symbols it references
/// * `rslits`: List of public symbols referenced by segments by address
pub fn process_segrefs(cslist: &mut [Vec<Pubsymref>], rslist: &mut [Vec<String>]) -> Vec<Segref> {
    let mut segrefs: Vec<Segref> = Vec::new();
    for i in 0..cslist.len().max(rslist.len()) {
        let matches = unify_refs(cslist, rslist, i);
        for (s, r) in matches {
            segrefs.push(Segref {
                location: i,
                name: String::from(s),
                goodness: r,
                description: None,
            });
        }
    }
    lazy_static! {
        // oh boy
        // this regex matches systematic symbols that represent load/store/arithmetic routines
        // found in the Keil libraries. A description is generated for these.
        // More info at http://www.keil.com/support/docs/1964.htm and http://www.keil.com/support/docs/1965.htm
        static ref DESC_RE: Regex =
            Regex::new(r"^\?C\?(?P<s>[SU])?(?P<t>(C|I|P|L|L0|FP))(((?P<f>(LD|ILD|LDI|ST|STK))(?P<m>((X|P|I)?DATA|CODE|O?PTR))(?P<n>0)?)|(?P<o>(ADD|SUB|MUL|DIV|CMP|AND|OR|XOR|NEG|NOT|SHL|SHR)))$").unwrap();
    }
    for segref in &mut segrefs {
        // add description if regex matches
        if let Some(cap) = DESC_RE.captures(&segref.name) {
            let mut desc = String::from("");
            desc.push_str(match cap.name("s").map(|x| x.as_str()) {
                Some("S") => "signed ",
                Some("U") => "unsigned ",
                Some(_) => "<unknown sign> ",
                None => "",
            });
            desc.push_str(match cap.name("t").unwrap().as_str() {
                "C" => "char (8-bit) ",
                "I" => "int (16-bit) ",
                "P" => "general pointer ",
                "L" => "long (32-bit) ",
                "L0" => "long (r3-r0) ",
                "FP" => "float ",
                _ => "<unknown type> ",
            });
            match cap.name("f").map(|x| x.as_str()) {
                Some(s) => {
                    desc.push_str(match s {
                        "LD" => "load from ",
                        "ILD" => "pre-increment load from ",
                        "LDI" => "post-increment load from ",
                        "ST" => "store to ",
                        "STK" => "constant store to ",
                        _ => "<unknown operation> of ",
                    });
                    desc.push_str(match cap.name("m").unwrap().as_str() {
                        "XDATA" => "xdata",
                        "PDATA" => "pdata (external ram)",
                        "IDATA" => "idata (indirect ram access)",
                        "DATA" => "data (direct ram access)",
                        "CODE" => "code space",
                        "OPTR" => "general pointer with offset",
                        "PTR" => "general pointer",
                        _ => "<unknown memory>",
                    });
                    if cap.name("n").is_some() {
                        desc.push_str(" into r3-r0");
                    }
                }
                None => {
                    desc.push_str(match cap.name("o").unwrap().as_str() {
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
                }
            }
            segref.description = Some(desc);
        }
    }
    segrefs
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Pubsymref {
    pub name: String,
    refs: Vec<(usize, String)>,
}

/// Prints all public symbols found in a table.
/// Symbols which are only found through references (such as main most of the time)
/// are put into parantheses.
pub fn print_segrefs(segrefs: &[Segref]) {
    println!("Address | {:<20} | Description", "Name",);
    for segref in segrefs {
        print!("{:<8} ", format!("0x{:04x}", segref.location));
        // indirect references are inside parens
        if segref.goodness == SymGoodness::RefOnly {
            print!(" {:<21} ", format!("({})", segref.name));
        } else if segref.goodness == SymGoodness::SymWithoutRef {
            print!(" {:<21} ", format!("[{}]", segref.name));
        } else {
            print!(" {:<21} ", segref.name);
        }
        match &segref.description {
            Some(des) => println!(" {}", des),
            // empty description
            None => println!(),
        }
    }
}

#[derive(PartialEq,Eq,PartialOrd,Ord,Clone,Debug)]
pub enum SymGoodness {
    RefOnly = 0,        // symbol is only a reference made by another segment
    SymWithoutRef = 1,  // symbol content is found in bytes, but references don't check out
    GoodSym = 2,        // symbol content appears in bytes and references also
}


/// Merges two lists and gives a boolean value for each if the item is only present in the second list.
fn unify_refs<'a>(
    cslist: &'a mut [Vec<Pubsymref>],
    rslist: &'a mut [Vec<String>],
    index: usize
) -> Vec<(&'a str, SymGoodness)> {
    let mut symarray: Vec<(&str, SymGoodness)> = Vec::new();
    // sort both lists so we can simple merge them from left to right
    if let Some(arr) = cslist.get_mut(index) {
        arr.sort();
    }
    if let Some(arr) = rslist.get_mut(index) {
        arr.sort();
    }
    lazy_static! {
        static ref EMPTY_A: Vec<Pubsymref> = Vec::new();
        static ref EMPTY_B: Vec<String> = Vec::new();
    }
    let a = cslist.get(index).unwrap_or(&EMPTY_A);
    let b = rslist.get(index).unwrap_or(&EMPTY_B);
    let mut aidx = 0;
    let mut bidx = 0;
    // if both indexes are at the end of their lists, we are finished
    while aidx < a.len() || bidx < b.len(){
        // add an item from `a` if there are still items left
        // if there are no items in b left, we don't have to compare them,
        // otherwise we compare them so that we don't just add all items from
        // a first
        if aidx < a.len() && (bidx >= b.len() || a[aidx].name <= b[bidx]) {
            let mut validrefs = true;
            for (idx, refname) in &a[aidx].refs {
                if let Some(subarr) = cslist.get(*idx) {
                    validrefs = validrefs && subarr.iter().find(|x| &x.name == refname).is_some();
                    if !validrefs {
                        break;
                    }
                }
                else {
                    validrefs = false;
                    break;
                }
            }
            if validrefs {
                symarray.push((&a[aidx].name, SymGoodness::GoodSym));
            }
            else {
                symarray.push((&a[aidx].name, SymGoodness::SymWithoutRef));
            }
            aidx += 1;
        }
        // the same case, but for b
        else if bidx < b.len() && (aidx >= a.len() || a[aidx].name >= b[bidx]) {
            symarray.push((&b[bidx], SymGoodness::RefOnly));
            bidx += 1;
        }
        else {
            panic!("Internal Error, this should not happen");
        };
    }
    // only use symbols with maximum goodness
    let maxel = symarray.iter().map(|(_,x)| x).max().unwrap_or(&SymGoodness::RefOnly).clone();
    let mut retarray = Vec::new();
    for (name, good) in symarray.into_iter().filter(|(_,x)| x == &maxel) {
        if retarray.last().map(|(s,_)| s) != Some(&name) {
            retarray.push((name,good));
        }
    };
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
    /// 0x10000
    /// * `checkref`: whether to check if local direct segment refernces are checked for validity
    /// (reduces noise)
    pub fn find_segments<'a>(
        self,
        buf: &[u8],
        cslist: &mut [Vec<Pubsymref>],
        rslist: &mut [Vec<String>],
        checkref: bool,
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
        for (segindex, x) in seglist.iter().enumerate() {
            for segpos in x {
                let mut invalid = false;
                let mut refvec: Vec<(usize,String)> = Vec::new();
                for fix in &self.segments[segindex].fixup {
                    invalid |= !match (&fix.code_ref.reftype, fix.find_target(buf, *segpos)) {
                        // for direct references, check if the other segment exists
                        (RefType::SegId(id), Some(target)) => seglist[*id].contains(&target),
                        // for public references, just add the name to the rslist
                        (RefType::Pubname(name), Some(target)) => {
                            if !rslist[target].contains(name) {
                                rslist[target].push(name.clone());
                            }
                            refvec.push((target, name.clone()));
                            true
                        }
                        // if the reference lands outside of the addresses of the buffer,
                        // the reference is invalid
                        (_, None) => false,
                    }
                }
                invalid &= !checkref;
                // short segments can create a lot of noise and we don't really care for them
                // anyway
                invalid |= self.segments[segindex].content_mask.len() < 3;
                if !invalid {
                    for (sym, offset) in &self.segments[segindex].pubsyms {
                        if cslist[segpos + offset]
                            .iter()
                            .find(|x| &x.name == sym)
                            .is_none()
                        {
                            // I feel bad about copying so much, but I'm lazy and not copying would
                            // probably require adding another vector somewhere, of which there
                            // are already more than enough
                            cslist[segpos + offset].push(Pubsymref {
                                name: sym.clone(),
                                refs: refvec.clone()
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
        println!("{}", start + subvalue.len() >= whstart + whole.len());
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
    /// are masked
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
    /// are masked
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

/// A fixup, which is a memory location within a segment which references another memory location
/// and is filled in later by the linker.
pub struct Fixup {
    refloc: usize,
    size: usize,
    addr_fun: Box<dyn Fn(&[u8], usize) -> usize + 'static>,
    code_ref: CodeRef,
}

impl Fixup {
    /// Creates a new Fixup
    ///
    /// # Arguments
    /// * `refloc`: location of fixup relative to segment begin
    /// * `size`: size of the region that is fixed up
    /// * `addr_fun`: a function that, given the bytes and absolute address of the fixup location,
    /// returns the location pointed to
    /// * `code_ref`: Type of reference (segment or public symbol)
    pub fn new(
        refloc: usize,
        size: usize,
        // kept general in case of ASLINK implementation
        addr_fun: Box<impl Fn(&[u8], usize) -> usize + 'static>,
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
                ((pos.wrapping_add(2)) & 0xf800 | ((bytes[0] as usize) << 8) & 7 | bytes[1] as usize) & 0xffff
            }),
            code_ref,
        }
    }
    pub fn relative(refloc: usize, code_ref: CodeRef) -> Self {
        Fixup {
            refloc,
            size: 1,
            addr_fun: Box::new(|bytes, pos| (pos.wrapping_add(1).wrapping_add((bytes[0]) as i8 as usize))),
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
        Some((self.addr_fun)(&buf[actual_position..], actual_position).wrapping_sub(self.code_ref.offset))
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
        assert_eq!(
            unify_refs(&mut vec![][..], &mut vec![vec![String::from("a"), String::from("b")]][..], 0),
            vec![(&"a"[..], SymGoodness::RefOnly), (&"b"[..], SymGoodness::RefOnly)]
        );
    }
    #[test]
    fn unify_refs_2() {
        assert_eq!(
            unify_refs(
                &mut vec![vec![
                    Pubsymref {
                        name: String::from("c"),
                        refs: vec![(4, String::from("k"))]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        refs: vec![(7, String::from("l"))]
                    }
                ]][..],
                &mut vec![vec![String::from("ba"), String::from("c")]][..],
                0
            ),
            vec![
                (&"ab"[..], SymGoodness::SymWithoutRef),
                (&"c"[..], SymGoodness::SymWithoutRef)
            ]
        );
    }
    #[test]
    fn unify_refs_3() {
        assert_eq!(
            unify_refs(
                &mut vec![vec![
                    Pubsymref {
                        name: String::from("c"),
                        refs: vec![(4, String::from("k"))]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        refs: vec![(3, String::from("k")), (7, String::from("l"))]
                    },
                    Pubsymref {
                        name: String::from("ab"),
                        refs: vec![(0, String::from("ab"))]
                    }
                ]][..],
                &mut vec![vec![String::from("ba"), String::from("c"), String::from("ab")]][..],
                0
            ),
            vec![
                (&"ab"[..], SymGoodness::GoodSym),
            ]
        );
    }
    #[test]
    fn find_masked_subvalue_oversize() {
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
            vec![]
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
        assert_eq!(
            check_at_location(
                0x10,
                &[0x10, 0x11, 0x12, 0x13],
                &[(0x91, 0x7f), (0x12, 0xfe), (0x13, 0x13)],
                0x11
            ),
            true
        );
    }
}
