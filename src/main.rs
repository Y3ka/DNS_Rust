#[macro_use]
extern crate simple_error;

mod byte_packet_buffer;
mod dns_packet;

pub use byte_packet_buffer::*;
pub use dns_packet::*;
use std::net::{UdpSocket, Ipv4Addr};
use simple_error::SimpleError;
/// Entrypoint of the server, binding to a UDP socket
fn main() -> Result<(), SimpleError> {
    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind("0.0.0.0:2053")
        .expect("Error creating socket on port 2053");
    
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => bail!(e),
        }
    }
}

/// Forward the request to a caching DNS server.
fn lookup(qname: &str, qtype: RecordType, server: (Ipv4Addr, u16)) -> Result<DnsPacket, SimpleError> {
    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))
        .expect("Error creating socket on port 43210");

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. The packet id is arbitrary.
    let mut packet = DnsPacket::new();

    packet.header.id = 1234;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestions::new(qname.to_string(), qtype));

    // Write the packet to a buffer...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server).expect("Error sending packet");
    
    // New `BytePacketBuffer` to prepare for receiving the response.
    // Ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).expect("Error receiving packet");

    DnsPacket::from_buffer(&mut res_buffer)
}

/// Handle query received on the socket
fn handle_query(socket: &UdpSocket) -> Result<(), SimpleError> {
    // Read a packet. Block until one is received
    let mut req_buffer = BytePacketBuffer::new();

    // Write the data into the buffer, and keep track of the source
    // in order to send our reply later on
    let (_, src_addr) = socket.recv_from(&mut req_buffer.buf).expect("Did not receive the data");
    
    // Parse the raw bytes into a "DnsPacket"
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Create and initialize the response packet
    let mut res_packet = DnsPacket::new();
    res_packet.header.id = request.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    // In the normal case, one question is present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        // Query is forwarded to the target server. If query fails, 'SERVFAIL' response
        // code is set to indicate it to the client. Otherwise question and response records are
        // copied into our response packet
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            res_packet.header.rescode = result.header.rescode;
            res_packet.questions.push(question);
            for rec in result.answers {
                println!("Answer: {:?}", rec);
                res_packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authorities: {:?}", rec);
                res_packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resources: {:?}", rec);
                res_packet.resources.push(rec);
            }
        } else {
            res_packet.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        // No question, indicate that the sender made something wrong
        res_packet.header.rescode = ResultCode::FORMERR;
    }

    // Encode the response and send it off
    let mut res_buffer = BytePacketBuffer::new();
    res_packet.write(&mut res_buffer)?;
    socket.send_to(&res_buffer.buf[0..res_buffer.pos], src_addr)
        .expect("Error sending response packet to user");
    Ok(())
    // let mut res_buffer = BytePacketBuffer::new();
    // res_packet.write(&mut res_buffer)?;

    // let len = res_buffer.pos();
    // let data = res_buffer.get_range(0, len)?;

    // socket.send_to(data, src_addr).expect("Error sending response packet to user");
    // Ok(())
}

/// Perform a recursive lookup, starting from root name server 198.41.0.4
fn recursive_lookup(qname: &str, qtype: RecordType) -> Result<DnsPacket, SimpleError> {
    // One of the Internet's 13 root servers a.root-servers.net (https://www.internic.net/domain/named.root)
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    // Since it might take an arbitrary number of steps, we enter an unbounded loop.
    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        // The next step is to send the query to the active server.
        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        // If there are entries in the answer section, and no errors, we are done!
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // We might also get a `NXDOMAIN` reply, which is the authoritative name servers
        // way of telling us that the name doesn't exist.
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
        // record in the additional section. If this succeeds, we can switch name server
        // and retry the loop.
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;

            continue;
        }

        // If not, we'll have to resolve the ip of a NS record. If no NS records exist,
        // we'll go with what the last server told us.
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        // Here we go down the rabbit hole by starting _another_ lookup sequence our current one. 
        // Hopefully, this will give us the IP of an appropriate name server.
        let recursive_response = recursive_lookup(&new_ns_name, RecordType::A)?;

        // Finally, we pick a random ip from the result, and restart the loop. If no such
        // record is available, we again return the last result we got.
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}
