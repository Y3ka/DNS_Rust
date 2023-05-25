use crate::BytePacketBuffer;
mod dns_res_code;
pub use dns_res_code::*;
use simple_error::SimpleError;

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(),SimpleError> {
        self.id = buffer.read_u16()?;
        
        let first_flags = buffer.read()?;
        self.response = (first_flags & 128) == 128;
        self.opcode = (first_flags & 120) >> 3;
        self.authoritative_answer = (first_flags & 4) == 4;
        self.truncated_message = (first_flags & 2) == 2;
        self.recursion_desired = (first_flags & 1) == 1;
        
        let second_flags = buffer.read()?;
        self.recursion_available = (second_flags & 128) == 128;
        self.z = (second_flags & 64) > 0;
        self.checking_disabled = (second_flags & 16) > 0;
        self.authed_data = (second_flags & 32) > 0;
        self.rescode = ResultCode::from_num(second_flags & 0x0F);

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), SimpleError> {
        buffer.write_u16(self.id)?;
        let first_flags: u8 = (self.response as u8) << 7
            | ((self.opcode as u8) << 3)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.truncated_message as u8) << 1)
            | (self.recursion_desired as u8);
        let second_flags: u8 = (self.rescode as u8)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7);
        buffer.write(first_flags)?;
        buffer.write(second_flags)?;
        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}