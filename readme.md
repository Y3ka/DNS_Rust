# DNS server in Rust

A simple DNS server that handles five types of record (A, NS, CNAME, MX, AAAA).

**_NOTE:_** This is a side project that I used to improved my knowledge on Rust and DNS protocol, if you are interested in a robust, compact and safe DNS server written in Rust go check [Hermes](https://github.com/EmilHernvall/hermes)

## Organization

### Modules

The code is organized in eight modules:

- **main.rs**: contains the logic that handles the request and performs the recursive query  
    - **byte_packet_buffers.rs**: contains the code to interact with the raw bytes of a DNS packet  
    - **dns_packet.rs**: contains the code used to represent a DNS packet object  
        - **dns_record.rs**: contains the code to represent a DNS record  
        - **dns_questions.rs**: contains the code to represent a DNS question  
            - **dns_record_types.rs**: contains the code to represent the DNS record type  
        - **dns_headers.rs**: contains the code to represent the dns packet header  
            - **dns_res_code.rs**: contains the code to represent the DNS response code  


### Documentation

You can generate the documentation for this crate with `cargo doc --open`.

The code is also extensively commented.

## Use

Just run `cargo run` in the local folder. You can also run `cargo build --release` and then run the binary generated in /target/release

The server is by default using the port 2053, make sure it is free.

You can test the server with the following command in another terminal: `dig @127.0.0.1 -p 2053 twitch.tv`

Receive the following answer:  

![Alt text](/resources/google_query.png "DNS server response")

And you can see logs (with the recursive lookup) on the terminal where you run the server:  

![Alt text](/resources/google_query_log.png "DNS server logs")
