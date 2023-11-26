//! Represent the DNS record
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::BytePacketBuffer;
use super::dns_questions::RecordType;
use simple_error::SimpleError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
/// Struct to represent a DNS record
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        host: String,
        priority: u16,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    } // 28
}

impl DnsRecord {
    /// Read record type from BytePacketBuffer
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, SimpleError> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = RecordType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            RecordType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            RecordType::UNKNOWN(_) => {
                buffer.steps(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
            RecordType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(DnsRecord::NS { 
                    domain: domain, 
                    host: host, 
                    ttl: ttl,
                }) 
            }
            RecordType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;
                Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl,
                })
            }
            RecordType::MX => {
                let mut host = String::new();
                let priority = buffer.read_u16()?;
                buffer.read_qname(&mut host)?;
                Ok(DnsRecord::MX { 
                    domain: domain, 
                    host: host, 
                    priority: priority, 
                    ttl: ttl, 
                })
            }
            RecordType::AAAA => {
                let mut bytes: Vec<u16> = Vec::new(); 
                for _ in 0..8 {
                    bytes.push(buffer.read_u16()?);
                }
                let addr = Ipv6Addr::new(
                    bytes[0],
                    bytes[1],
                    bytes[2],
                    bytes[3],
                    bytes[4],
                    bytes[5],
                    bytes[6],
                    bytes[7],
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
        }
    }

    /// Write a record into a BytePacketBuffer and return the size of this record
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, SimpleError> {
        let start_pos = buffer.pos();

        match self {
            DnsRecord::A { domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(RecordType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?;
                for byte in addr.octets() {
                    buffer.write(byte)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                // buffer.write_qname(domain)?;
                // buffer.write_u16(*qtype)?;
                // buffer.write_u16(1)?;
                // buffer.write_u32(*ttl)?;
                // buffer.write_u16(*data_len)?;
                print!("Skipping record: {:?}", self);
            }
            DnsRecord::AAAA { domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(RecordType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(16)?;
                for two_bytes in addr.segments() {
                    buffer.write_u16(two_bytes)?;
                }
            }
            DnsRecord::CNAME { domain, host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(RecordType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(0)?;
                let start_position = buffer.pos();
                buffer.write_qname(host)?;
                let size: usize = buffer.pos() - start_position;
                buffer.set_u16(start_position - 1, size as u16)?;
            }
            DnsRecord::NS { domain, host, ttl, } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(RecordType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(0)?;
                let start_position = buffer.pos();

                buffer.write_qname(host)?;
                let size = buffer.pos() - start_position;
                buffer.set_u16(start_pos - 1, size as u16)?;
            }
            DnsRecord::MX { domain, priority, host, ttl, } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(RecordType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(0)?;
                
                let start_position = buffer.pos();
                buffer.write_u16(*priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - start_position;
                buffer.set_u16(start_position - 1, size as u16)?;
            }
        }   
        Ok(buffer.pos() - start_pos)
    }
}