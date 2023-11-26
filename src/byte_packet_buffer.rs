//! This module implements all the necessary tooling for representing and interacting with the raw bytes of a DNS packet

use std::str;
use simple_error::SimpleError;

/// Struct that represents a raw DNS packet
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// Create a new buffer that holds the package content received
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer { 
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Return the current position within the buffer
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Steps forward within the buffer
    pub fn steps(&mut self, steps: usize) -> Result<(),SimpleError> {
        self.pos += steps;
        Ok(())
    }

    /// Change the buffer position
    pub fn seek(&mut self, pos: usize) -> Result<(),SimpleError> {
        self.pos = pos;
        Ok(())
    }

    /// Read one byte and make one step forward
    pub fn read(&mut self) -> Result<u8, SimpleError> {
        if self.pos >= 512 {
            bail!("End of buffer")
        }
        let single_byte = self.buf[self.pos];
        self.steps(1)?;
        Ok(single_byte)
    }

    /// Get the byte at the current position
    pub fn get(&self, pos: usize) -> Result<u8, SimpleError> {
        if pos >= 512 {
            bail!("End of buffer")
        }
        Ok(self.buf[pos])
    }

    /// Get a range of byte starting at index start and of length len
    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8], SimpleError> {
        if start + len >= 512 {
            bail!("End of buffer");
        }
        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes and make two steps forward
    pub fn read_u16(&mut self) -> Result<u16, SimpleError> {
        if self.pos >= 511 {
            bail!("End of buffer");
        }
        let two_bytes = ((self.read()? as u16) << 8) ^ (self.read()? as u16);
        Ok(two_bytes)
    }

    /// Read four bytes and make four steps forward
    pub fn read_u32(&mut self) -> Result<u32, SimpleError> {
        if self.pos >= 509 {
            bail!("End of buffer");
        }
        let four_bytes = ((self.read_u16()? as u32) << 16) ^ (self.read_u16()? as u32);
        Ok(four_bytes)
    }

    /// Read qname
    /// In case the length bytes prependings name labels have its two MSB set to 1
    /// we need to jump to the position indicated by rest of the 6 bits
    /// # Example 
    /// 0xC00C -> jump to position 12 (0x0C) and read from there
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), SimpleError> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the buffer. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut shared_pos = self.pos();
        
        // Track if we jumped or not
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;
        
        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delimiter = "";

        loop {
            if jumps_performed > max_jumps {
                bail!(format!("Limit of {} jumps exceeded", max_jumps).as_str());
            }

            // At this point, we're always at the beginning of a label. Labels start with length byte.
            let len = self.get(shared_pos)?;
            //Check if the two MSB of the length are set and jump in this case
            if (len & 0xC0) == 0xC0  {
                
                // Update buffer position past the current label since we are going to jump
                if !jumped {
                    self.seek(shared_pos + 2)?;
                }

                // Read second byte and calculate offset for the jump
                let second_byte = self.get(shared_pos + 1)? as u16;
                let offset = (((len as u16) ^ 0x00C0) << 8) | second_byte;
                
                // Perform jump
                shared_pos = offset as usize;
                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                shared_pos += 1;
            
                //Empty label means end of the domain name
                if len == 0 {
                    break;
                }
                
                outstr.push_str(delimiter);

                let buf_slice = self.get_range(shared_pos, len as usize)?;
                // Transform &[u8] to &str and add it to outstr
                outstr.push_str(&str::from_utf8(buf_slice).expect("bytes are not valid UTF-8").to_lowercase());
                delimiter = ".";
                shared_pos += len as usize
            }
        }
        
        // Update buffer position at the end of the read in case we did not jump
        // It was already updated in case of a jump
        if !jumped {
            self.seek(shared_pos)?;
        }
        
        Ok(())
    }

    /// Write the next byte of the buffer
    pub fn write(&mut self, val: u8) -> Result<(), SimpleError> {
        if self.pos >= 512 {
            bail!("End of buffer")
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// Write the next two bytes of the buffer
    pub fn write_u16(&mut self, val: u16) -> Result<(), SimpleError> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    /// Write the next four bytes of the buffer
    pub fn write_u32(&mut self, val: u32) -> Result<(), SimpleError> {
        self.write((val >> 24) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    /// Write the query name in labeled form (domain)
    pub fn write_qname(&mut self, qname: &str) -> Result<(), SimpleError> {
        for label in qname.split(".") {
            let length = label.len();
            if length > 0x3f {
                bail!("Single label exceeds 63 characters of length")
            }
            self.write(length as u8)?;
            for byte in label.as_bytes() {
                self.write(*byte)?;
            }
        }
        self.write(0)?;

        Ok(())
    }

    /// Write 1 byte at position pos
    fn set(&mut self, pos: usize, val: u8) -> Result<(), SimpleError> {
        self.buf[pos] = val;

        Ok(())
    }

    /// Write 2 bytes at position pos and pos+1
    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), SimpleError> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}