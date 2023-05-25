use crate::BytePacketBuffer;
mod dns_query_type;
pub use dns_query_type::*;
use simple_error::SimpleError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestions {
    pub name: String,
    pub qtype: QueryType,
    //pub class: bool -> in practice always one
}

impl DnsQuestions {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestions {
        DnsQuestions {
            name,
            qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), SimpleError> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16();

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), SimpleError> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1)?;

        Ok(())
    }

}