//! Represent the RecordType
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
/// Enum to represent record types
pub enum RecordType {
    UNKNOWN(u16),
    A, //1
    NS, //2
    CNAME, //5
    MX, //15
    AAAA, //28
}

impl RecordType {
    /// Convert RecordType enum into the bytes
    pub fn to_num(&self) -> u16 {
        match *self {
            RecordType::A => 1,
            RecordType::UNKNOWN(num) => num,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
            RecordType::AAAA => 28,
        }
    }
    /// Convert bytes into a RecordType
    pub fn from_num(num: u16) -> RecordType {
        match num {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            28 => RecordType::AAAA,
            _ => RecordType::UNKNOWN(num),

        }
    }
}
