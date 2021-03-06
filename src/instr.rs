/// An enum specifying the types of opcode an 8051 instruction can have.
pub enum InsType {
    RESRV,
    ACALL,
    ADD,
    ADDC,
    AJMP,
    ANL,
    CJNE,
    CLR,
    CPL,
    DA,
    DEC,
    DIV,
    DJNZ,
    INC,
    JB,
    JBC,
    JC,
    JMP,
    JNB,
    JNC,
    JNZ,
    JZ,
    LCALL,
    LJMP,
    MOV,
    MOVC,
    MOVX,
    MUL,
    NOP,
    ORL,
    POP,
    PUSH,
    RET,
    RETI,
    RL,
    RLC,
    RR,
    RRC,
    SETB,
    SJMP,
    SUBB,
    SWAP,
    XCH,
    XCHD,
    XRL,
}

/// a table specifying the data for each 8051 opcode
/// where the offset corresponds to the opcode
static INSTR_INFO: [(u8, InsType); 256] = [
    (1, InsType::NOP),
    (2, InsType::AJMP),
    (3, InsType::LJMP),
    (1, InsType::RR),
    (1, InsType::INC),
    (2, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (1, InsType::INC),
    (3, InsType::JBC),
    (2, InsType::ACALL),
    (3, InsType::LCALL),
    (1, InsType::RRC),
    (1, InsType::DEC),
    (2, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (1, InsType::DEC),
    (3, InsType::JB),
    (2, InsType::AJMP),
    (1, InsType::RET),
    (1, InsType::RL),
    (2, InsType::ADD),
    (2, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (1, InsType::ADD),
    (3, InsType::JNB),
    (2, InsType::ACALL),
    (1, InsType::RETI),
    (1, InsType::RLC),
    (2, InsType::ADDC),
    (2, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (1, InsType::ADDC),
    (2, InsType::JC),
    (2, InsType::AJMP),
    (2, InsType::ORL),
    (3, InsType::ORL),
    (2, InsType::ORL),
    (2, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (1, InsType::ORL),
    (2, InsType::JNC),
    (2, InsType::ACALL),
    (2, InsType::ANL),
    (3, InsType::ANL),
    (2, InsType::ANL),
    (2, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (1, InsType::ANL),
    (2, InsType::JZ),
    (2, InsType::AJMP),
    (2, InsType::XRL),
    (3, InsType::XRL),
    (2, InsType::XRL),
    (2, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (1, InsType::XRL),
    (2, InsType::JNZ),
    (2, InsType::ACALL),
    (2, InsType::ORL),
    (1, InsType::JMP),
    (2, InsType::MOV),
    (3, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::SJMP),
    (2, InsType::AJMP),
    (2, InsType::ANL),
    (1, InsType::MOVC),
    (1, InsType::DIV),
    (3, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (3, InsType::MOV),
    (2, InsType::ACALL),
    (2, InsType::MOV),
    (1, InsType::MOVC),
    (2, InsType::SUBB),
    (2, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (1, InsType::SUBB),
    (2, InsType::ORL),
    (2, InsType::AJMP),
    (2, InsType::MOV),
    (1, InsType::INC),
    (1, InsType::MUL),
    (1, InsType::RESRV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::MOV),
    (2, InsType::ANL),
    (2, InsType::ACALL),
    (2, InsType::CPL),
    (1, InsType::CPL),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (3, InsType::CJNE),
    (2, InsType::PUSH),
    (2, InsType::AJMP),
    (2, InsType::CLR),
    (1, InsType::CLR),
    (1, InsType::SWAP),
    (2, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (1, InsType::XCH),
    (2, InsType::POP),
    (2, InsType::ACALL),
    (2, InsType::SETB),
    (1, InsType::SETB),
    (1, InsType::DA),
    (3, InsType::DJNZ),
    (1, InsType::XCHD),
    (1, InsType::XCHD),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (2, InsType::DJNZ),
    (1, InsType::MOVX),
    (2, InsType::AJMP),
    (1, InsType::MOVX),
    (1, InsType::MOVX),
    (1, InsType::CLR),
    (2, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOVX),
    (2, InsType::ACALL),
    (1, InsType::MOVX),
    (1, InsType::MOVX),
    (1, InsType::CPL),
    (2, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
    (1, InsType::MOV),
];

/// An iterator that iterates over a buffer and makes
/// steps corresponding to the size the opcode at the
/// address has.
pub struct Instructeam<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// An 8051 Instruction, contains the instruction type,
/// the bytes of the instruction and the address.
pub struct Instruction<'a> {
    pub itype: &'static InsType,
    pub bytes: &'a [u8],
    pub pos: usize,
}

impl<'a> Instructeam<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Instructeam { bytes, pos: 0 }
    }
}

impl<'a> Iterator for Instructeam<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // get the opcode at the current address
        let opcode = *self.bytes.get(self.pos)? as usize;
        let (u8len, itype) = &INSTR_INFO[opcode];
        let len = *u8len as usize;
        // if the current instruction doesn't fit into the buffer
        // end the iterator
        if self.bytes.len() < self.pos + len {
            self.pos = self.bytes.len();
            None
        } else {
            // else we can give the instruction
            let retstruct: Instruction = Instruction {
                itype,
                bytes: &self.bytes[self.pos..self.pos + len],
                pos: self.pos,
            };
            // and continue at the next instruction
            self.pos += len;
            Some(retstruct)
        }
    }
}

impl<'a> Instruction<'a> {
    /// Given a instruction, this function returns the jump address of the jump if it is a jump
    /// instruction, else None.
    /// If the instruction is not within the first 64k bytes, the jump addresses is in the same 64k
    /// block.
    pub fn get_jump_target(&self) -> Option<usize> {
        let in_block = match self.itype {
            InsType::LJMP | InsType::LCALL => {
                usize::from(self.bytes[1]) << 8 | usize::from(self.bytes[2])
            }
            InsType::AJMP | InsType::ACALL => {
                usize::from(self.bytes[1])
                    | ((usize::from(self.bytes[0]) & 0xe0) << 3)
                    | ((self.pos + 2) & 0xf800)
            }
            InsType::SJMP
            | InsType::JZ
            | InsType::JNZ
            | InsType::JC
            | InsType::JNC
            | InsType::JNB
            | InsType::JB
            | InsType::JBC
            | InsType::CJNE
            | InsType::DJNZ => usize::wrapping_add(
                usize::wrapping_add(self.pos, self.bytes.len()),
                *self.bytes.last().unwrap() as i8 as usize,
            ),
            _ => return None,
        };
        // modify to be within 64k block
        Some(!0xffff & self.pos | in_block & 0xffff)
    }
}
