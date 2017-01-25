#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;

extern crate suricata_interface;
use suricata_interface::*;

/// Declare all parsers
///
/// Since this crate will produce a library, declaring the parsers is enough to
/// instanciate all functions.
extern crate suricata_dns;
use suricata_dns::*;

extern crate suricata_quic;
use suricata_quic::*;



// Starting from here, all code is optional


// Example code to store all parsers in a single HashMap
enum AllParsers<'a> {
    Quic(QuicParser<'a>),
}

lazy_static! {
    static ref HASHMAP: HashMap<String, AllParsers<'static>> = {
        let mut m = HashMap::new();
        m.insert("quic".to_string(),AllParsers::Quic(QuicParser::new(b"Quic")));
        m
    };
}

/// This function can be used for ex, to register all parsers to C,
/// or to initialize some runtime functions, etc.
#[no_mangle]
pub extern "C" fn suricata_rust_init() -> u32 {
    // let mut m : HashMap<String,AllParsers> = HashMap::new();
    // m.insert("quic".to_string(),AllParsers::Quic(QuicParser::new(b"Quic")));

    for (name,parser) in HASHMAP.iter() {
        match *parser {
            AllParsers::Quic(ref q) => (),
            // _ => (),
        }
    }

    0
}
