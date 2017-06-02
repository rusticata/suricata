extern crate libc;

use std;
use std::mem;
use libc::c_char;

use suricata_interface::rparser::*;

use ssh_parser::*;

use nom::IResult;


#[no_mangle]
pub static SSH_EVENTS: &[MyEvent]  = &[
    r_event!(b"INVALID_STATE\0", 0),
    r_event!(b"OLD_VERSION\0", 1),
    r_event!(0, -1),
];


#[derive(Debug)]
enum SshState {
    Identification,
    KeyExchangeInit,
    KeyExchange,
    KeyExchangeFinish,
    Encrypted,
}


pub struct SshParser<'a> {
    name: Option<&'a [u8]>,
    tcp_buffer: Vec<u8>,
    state: SshState,
    events: Vec<u32>,
}

impl<'a> RParser for SshParser<'a> {

    fn parse<'b>(&mut self, i: &'b [u8], direction: u8) -> u32 {
        let mut ret = R_STATUS_OK;
        let mut idx: usize = 0;
        let mut v: Vec<u8>;

        // work only on server response for now
        if direction == 0 {
            return R_STATUS_OK;
        }

        while idx < i.len() {
            // if we already have buffered data then do reassembly
            let mut buffer = if self.tcp_buffer.len() > 0 {
                // do not exceed buffer capacity to avoid DoS
                let free = self.tcp_buffer.capacity() - self.tcp_buffer.len();

                if free == 0 {
                    // if the buffer was already full and the parsing failed
                    // then we cannot do anything.
                    ret |= R_STATUS_FAIL;
                    break;
                }

                let n = if free > i.len() - idx { i.len() - idx } else { free };
                v = self.tcp_buffer.split_off(0);
                v.extend_from_slice(&i[idx..n]);
                debug!("reassembly, buffer is now {} bytes", v.len());
                idx = n;
                v.as_slice()
            } else {
                idx = i.len();
                i
            };

            while buffer.len() > 0 {
                match self.state {
                    SshState::Encrypted => break,
                    SshState::Identification => match parse_ssh_identification(buffer) {
                        IResult::Done(rst, ident) => {
                            buffer = rst;
                            ret |= self.handle_identification(ident);
                        },
                        IResult::Incomplete(_) => {
                            self.tcp_buffer.extend_from_slice(buffer);
                            break;
                        },
                        IResult::Error(_) => {
                            ret |= R_STATUS_FAIL;
                            break;
                        },
                    },
                    _ => match parse_ssh_packet(buffer) {
                        IResult::Done(rst, (pkt, _)) => {
                            buffer = rst;
                            ret |= self.handle_packet(pkt);
                        },
                        IResult::Incomplete(_) => {
                            self.tcp_buffer.extend_from_slice(buffer);
                            break;
                        },
                        IResult::Error(_) => {
                            ret |= R_STATUS_FAIL;
                            break;
                        },
                    },
                };
            }
        }
        ret
    }

    fn get_next_event(&mut self) -> u32 {
        match self.events.pop() {
            None     => R_NO_MORE_EVENTS,
            Some(ev) => ev,
        }
    }

}


impl<'a> SshParser<'a> {

    pub fn new(name: &'a [u8]) -> SshParser<'a> {
        SshParser {
            name: Some(name),
            // Minimum full packet lenght required by RFC4253
            tcp_buffer: Vec::with_capacity(35000),
            state: SshState::Identification,
            events: Vec::new(),
        }
    }

    pub fn handle_identification(&mut self, ident: (Vec<&[u8]>, SshVersion)) -> u32 {
        let mut ret: u32 = R_STATUS_OK;

        self.state = SshState::KeyExchangeInit;
        if ident.1.proto != b"2.0" {
            self.events.push(1);
            ret |= R_STATUS_EVENTS;
        }
        ret
    }

    pub fn handle_packet(&mut self, pkt: SshPacket) -> u32 {
        let mut ret: u32 = R_STATUS_OK;

        debug!("state {:?} packet! {:?}", self.state, pkt);
        match (&self.state, pkt) {
            (&SshState::KeyExchangeInit, SshPacket::KeyExchange(_)) => {
                self.state = SshState::KeyExchange;
            },
            (&SshState::KeyExchange, SshPacket::DiffieHellmanReply(_)) => {
                self.state = SshState::KeyExchangeFinish;
            },
            (&SshState::KeyExchangeFinish, SshPacket::NewKeys) => {
                self.state = SshState::Encrypted;
            },
            (_, _) => {
                ret = R_STATUS_FAIL | R_STATUS_EVENTS;
                self.events.push(0);
                warn!("unexpected packet for this state");
            }
        };
        ret
    }

}


fn ssh_probe(i: &[u8]) -> bool {
    if i.len() <= 4 { return false; }
    // this is not always true as the server can prepend the identification
    // with any number of line not starting with SSH-.
    i[0] == 'S' as u8 && i[1] == 'S' as u8 && i[2] == 'H' as u8 && i[3] == '-' as u8
}

r_declare_state_new!(r_ssh_state_new,SshParser,b"SSH state");
r_declare_state_free!(r_ssh_state_free,SshParser,{ () });

r_implement_probe!(r_ssh_probe,ssh_probe,ALPROTO_SSH);
r_implement_parse!(r_ssh_parse,SshParser);
