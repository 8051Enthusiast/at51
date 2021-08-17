/// An enum specifying the types of opcode an 8051 instruction can have.
pub enum InsType {
    Resrv,
    Acall,
    Add,
    Addc,
    Ajmp,
    Anl,
    Cjne,
    Clr,
    Cpl,
    Da,
    Dec,
    Div,
    Djnz,
    Inc,
    Jb,
    Jbc,
    Jc,
    Jmp,
    Jnb,
    Jnc,
    Jnz,
    Jz,
    Lcall,
    Ljmp,
    Mov,
    Movc,
    Movx,
    Mul,
    Nop,
    Orl,
    Pop,
    Push,
    Ret,
    Reti,
    Rl,
    Rlc,
    Rr,
    Rrc,
    Setb,
    Sjmp,
    Subb,
    Swap,
    Xch,
    Xchd,
    Xrl,
}

/// a table specifying the data for each 8051 opcode
/// where the offset corresponds to the opcode
static INSTR_INFO: [(u8, InsType); 256] = [
    (1, InsType::Nop),
    (2, InsType::Ajmp),
    (3, InsType::Ljmp),
    (1, InsType::Rr),
    (1, InsType::Inc),
    (2, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (1, InsType::Inc),
    (3, InsType::Jbc),
    (2, InsType::Acall),
    (3, InsType::Lcall),
    (1, InsType::Rrc),
    (1, InsType::Dec),
    (2, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (1, InsType::Dec),
    (3, InsType::Jb),
    (2, InsType::Ajmp),
    (1, InsType::Ret),
    (1, InsType::Rl),
    (2, InsType::Add),
    (2, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (1, InsType::Add),
    (3, InsType::Jnb),
    (2, InsType::Acall),
    (1, InsType::Reti),
    (1, InsType::Rlc),
    (2, InsType::Addc),
    (2, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (1, InsType::Addc),
    (2, InsType::Jc),
    (2, InsType::Ajmp),
    (2, InsType::Orl),
    (3, InsType::Orl),
    (2, InsType::Orl),
    (2, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (1, InsType::Orl),
    (2, InsType::Jnc),
    (2, InsType::Acall),
    (2, InsType::Anl),
    (3, InsType::Anl),
    (2, InsType::Anl),
    (2, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (1, InsType::Anl),
    (2, InsType::Jz),
    (2, InsType::Ajmp),
    (2, InsType::Xrl),
    (3, InsType::Xrl),
    (2, InsType::Xrl),
    (2, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (1, InsType::Xrl),
    (2, InsType::Jnz),
    (2, InsType::Acall),
    (2, InsType::Orl),
    (1, InsType::Jmp),
    (2, InsType::Mov),
    (3, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Sjmp),
    (2, InsType::Ajmp),
    (2, InsType::Anl),
    (1, InsType::Movc),
    (1, InsType::Div),
    (3, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (3, InsType::Mov),
    (2, InsType::Acall),
    (2, InsType::Mov),
    (1, InsType::Movc),
    (2, InsType::Subb),
    (2, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (1, InsType::Subb),
    (2, InsType::Orl),
    (2, InsType::Ajmp),
    (2, InsType::Mov),
    (1, InsType::Inc),
    (1, InsType::Mul),
    (1, InsType::Resrv),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Mov),
    (2, InsType::Anl),
    (2, InsType::Acall),
    (2, InsType::Cpl),
    (1, InsType::Cpl),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (3, InsType::Cjne),
    (2, InsType::Push),
    (2, InsType::Ajmp),
    (2, InsType::Clr),
    (1, InsType::Clr),
    (1, InsType::Swap),
    (2, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (1, InsType::Xch),
    (2, InsType::Pop),
    (2, InsType::Acall),
    (2, InsType::Setb),
    (1, InsType::Setb),
    (1, InsType::Da),
    (3, InsType::Djnz),
    (1, InsType::Xchd),
    (1, InsType::Xchd),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (2, InsType::Djnz),
    (1, InsType::Movx),
    (2, InsType::Ajmp),
    (1, InsType::Movx),
    (1, InsType::Movx),
    (1, InsType::Clr),
    (2, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Movx),
    (2, InsType::Acall),
    (1, InsType::Movx),
    (1, InsType::Movx),
    (1, InsType::Cpl),
    (2, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
    (1, InsType::Mov),
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
            InsType::Ljmp | InsType::Lcall => {
                usize::from(self.bytes[1]) << 8 | usize::from(self.bytes[2])
            }
            InsType::Ajmp | InsType::Acall => {
                usize::from(self.bytes[1])
                    | ((usize::from(self.bytes[0]) & 0xe0) << 3)
                    | ((self.pos + 2) & 0xf800)
            }
            InsType::Sjmp
            | InsType::Jz
            | InsType::Jnz
            | InsType::Jc
            | InsType::Jnc
            | InsType::Jnb
            | InsType::Jb
            | InsType::Jbc
            | InsType::Cjne
            | InsType::Djnz => usize::wrapping_add(
                usize::wrapping_add(self.pos, self.bytes.len()),
                *self.bytes.last().unwrap() as i8 as usize,
            ),
            _ => return None,
        };
        // modify to be within 64k block
        Some(!0xffff & self.pos | in_block & 0xffff)
    }
}
