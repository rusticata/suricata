/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

extern crate libc;
extern crate nom;

use std;
use std::mem::transmute;

use log::*;
use applayer::LoggerFlags;
use core;
use dns::parser;

use std::ffi::CString;

use rparser::RParser;
use cparser::{RustParser,StringToAppProto};

lazy_static! {
    pub static ref ALPROTO_DNS : u16 = {
        let name = "dns";
        let al_proto = unsafe{ StringToAppProto(name.as_ptr()) };
        if (al_proto == 0) || (al_proto == 0xffff) {
            panic!("Application layer protocol registration failed for protocol {}", name);
        };
        al_proto
    };

    pub static ref DnsTCPParser : RustParser = {
        RustParser::new(
            "dns", 6, "53", 0,
            *ALPROTO_DNS,
            std::ptr::null(),
            rs_dns_probe_tcp,
            rs_dns_state_tcp_new, rs_dns_state_free
        )
    };

}

/// DNS record types.
pub const DNS_RTYPE_A:     u16 = 1;
pub const DNS_RTYPE_CNAME: u16 = 5;
pub const DNS_RTYPE_SOA:   u16 = 6;
pub const DNS_RTYPE_PTR:   u16 = 12;
pub const DNS_RTYPE_MX:    u16 = 15;
pub const DNS_RTYPE_AAAA:  u16 = 28;
pub const DNS_RTYPE_SSHFP: u16 = 44;
pub const DNS_RTYPE_RRSIG: u16 = 46;

/// DNS record types.
pub const DNS_RECORD_TYPE_A           : u16 = 1;
pub const DNS_RECORD_TYPE_NS          : u16 = 2;
pub const DNS_RECORD_TYPE_MD          : u16 = 3;   // Obsolete
pub const DNS_RECORD_TYPE_MF          : u16 = 4;   // Obsolete
pub const DNS_RECORD_TYPE_CNAME       : u16 = 5;
pub const DNS_RECORD_TYPE_SOA         : u16 = 6;
pub const DNS_RECORD_TYPE_MB          : u16 = 7;   // Experimental
pub const DNS_RECORD_TYPE_MG          : u16 = 8;   // Experimental
pub const DNS_RECORD_TYPE_MR          : u16 = 9;   // Experimental
pub const DNS_RECORD_TYPE_NULL        : u16 = 10;  // Experimental
pub const DNS_RECORD_TYPE_WKS         : u16 = 11;
pub const DNS_RECORD_TYPE_PTR         : u16 = 12;
pub const DNS_RECORD_TYPE_HINFO       : u16 = 13;
pub const DNS_RECORD_TYPE_MINFO       : u16 = 14;
pub const DNS_RECORD_TYPE_MX          : u16 = 15;
pub const DNS_RECORD_TYPE_TXT         : u16 = 16;
pub const DNS_RECORD_TYPE_RP          : u16 = 17;
pub const DNS_RECORD_TYPE_AFSDB       : u16 = 18;
pub const DNS_RECORD_TYPE_X25         : u16 = 19;
pub const DNS_RECORD_TYPE_ISDN        : u16 = 20;
pub const DNS_RECORD_TYPE_RT          : u16 = 21;
pub const DNS_RECORD_TYPE_NSAP        : u16 = 22;
pub const DNS_RECORD_TYPE_NSAPPTR     : u16 = 23;
pub const DNS_RECORD_TYPE_SIG         : u16 = 24;
pub const DNS_RECORD_TYPE_KEY         : u16 = 25;
pub const DNS_RECORD_TYPE_PX          : u16 = 26;
pub const DNS_RECORD_TYPE_GPOS        : u16 = 27;
pub const DNS_RECORD_TYPE_AAAA        : u16 = 28;
pub const DNS_RECORD_TYPE_LOC         : u16 = 29;
pub const DNS_RECORD_TYPE_NXT         : u16 = 30;  // Obosolete
pub const DNS_RECORD_TYPE_SRV         : u16 = 33;
pub const DNS_RECORD_TYPE_ATMA        : u16 = 34;
pub const DNS_RECORD_TYPE_NAPTR       : u16 = 35;
pub const DNS_RECORD_TYPE_KX          : u16 = 36;
pub const DNS_RECORD_TYPE_CERT        : u16 = 37;
pub const DNS_RECORD_TYPE_A6          : u16 = 38;  // Obsolete
pub const DNS_RECORD_TYPE_DNAME       : u16 = 39;
pub const DNS_RECORD_TYPE_OPT         : u16 = 41;
pub const DNS_RECORD_TYPE_APL         : u16 = 42;
pub const DNS_RECORD_TYPE_DS          : u16 = 43;
pub const DNS_RECORD_TYPE_SSHFP       : u16 = 44;
pub const DNS_RECORD_TYPE_IPSECKEY    : u16 = 45;
pub const DNS_RECORD_TYPE_RRSIG       : u16 = 46;
pub const DNS_RECORD_TYPE_NSEC        : u16 = 47;
pub const DNS_RECORD_TYPE_DNSKEY      : u16 = 48;
pub const DNS_RECORD_TYPE_DHCID       : u16 = 49;
pub const DNS_RECORD_TYPE_NSEC3       : u16 = 50;
pub const DNS_RECORD_TYPE_NSEC3PARAM  : u16 = 51;
pub const DNS_RECORD_TYPE_TLSA        : u16 = 52;
pub const DNS_RECORD_TYPE_HIP         : u16 = 55;
pub const DNS_RECORD_TYPE_CDS         : u16 = 59;
pub const DNS_RECORD_TYPE_CDNSKEY     : u16 = 60;
pub const DNS_RECORD_TYPE_SPF         : u16 = 99;  // Obsolete
pub const DNS_RECORD_TYPE_TKEY        : u16 = 249;
pub const DNS_RECORD_TYPE_TSIG        : u16 = 250;
pub const DNS_RECORD_TYPE_MAILA       : u16 = 254; // Obsolete
pub const DNS_RECORD_TYPE_ANY         : u16 = 255;
pub const DNS_RECORD_TYPE_URI         : u16 = 256;

/// DNS error codes.
pub const DNS_RCODE_NOERROR:  u16 = 0;
pub const DNS_RCODE_FORMERR:  u16 = 1;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;

/// The maximum number of transactions to keep in the queue pending
/// processing before they are aggressively purged. Due to the
/// stateless nature of this parser this is rarely needed, especially
/// when one call to parse a request parses and a single request, and
/// likewise for responses.
///
/// Where this matters is when one TCP buffer contains multiple
/// requests are responses and one call into the parser creates
/// multiple transactions. In this case we have to hold onto
/// transactions longer than until handling the next transaction so it
/// gets logged.
const MAX_TRANSACTIONS: usize = 32;

#[repr(u32)]
pub enum DNSEvent {
    UnsolicitedResponse = 0,
    MalformedData,
    NotRequest,
    NotResponse,
    ZFlagSet,
    Flooded,
    StateMemCapReached,
}

#[derive(Debug,PartialEq)]
pub struct DNSHeader {
    pub tx_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer_rr: u16,
    pub authority_rr: u16,
    pub additional_rr: u16,
}

#[derive(Debug)]
pub struct DNSQueryEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
}

impl DNSQueryEntry {

    pub fn name(&self) -> &str {
        let r = std::str::from_utf8(&self.name);
        if r.is_err() {
            return "";
        }
        return r.unwrap();
    }

}

#[derive(Debug,PartialEq)]
pub struct DNSAnswerEntry {
    pub name: Vec<u8>,
    pub rrtype: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub data_len: u16,
    pub data: Vec<u8>,
}

impl DNSAnswerEntry {

    pub fn name(&self) -> &str {
        let r = std::str::from_utf8(&self.name);
        if r.is_err() {
            return "";
        }
        return r.unwrap();
    }

    pub fn data_to_string(&self) -> &str {
        let r = std::str::from_utf8(&self.data);
        if r.is_err() {
            return "";
        }
        return r.unwrap();
    }

}

#[derive(Debug)]
pub struct DNSRequest {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
}

#[derive(Debug)]
pub struct DNSResponse {
    pub header: DNSHeader,
    pub queries: Vec<DNSQueryEntry>,
    pub answers: Vec<DNSAnswerEntry>,
    pub authorities: Vec<DNSAnswerEntry>,
}

#[derive(Debug)]
pub struct DNSTransaction {
    pub id: u64,
    pub request: Option<DNSRequest>,
    pub response: Option<DNSResponse>,
    pub logged: LoggerFlags,
    pub de_state: Option<*mut core::DetectEngineState>,
    pub events: *mut core::AppLayerDecoderEvents,
}

impl DNSTransaction {

    pub fn new() -> DNSTransaction {
        return DNSTransaction{
            id: 0,
            request: None,
            response: None,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
    }

    /// Get the DNS transactions ID (not the internal tracking ID).
    pub fn tx_id(&self) -> u16 {
        for request in &self.request {
            return request.header.tx_id;
        }
        for response in &self.response {
            return response.header.tx_id;
        }

        // Shouldn't happen.
        return 0;
    }

    /// Get the reply code of the transaction. Note that this will
    /// also return 0 if there is no reply.
    pub fn rcode(&self) -> u16 {
        for response in &self.response {
            return response.header.flags & 0x000f;
        }
        return 0;
    }

}

impl Drop for DNSTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct DNSState {
    // Internal transaction ID.
    pub tx_id: u64,

    // Transactions.
    pub transactions: Vec<DNSTransaction>,

    pub de_state_count: u64,

    pub events: u16,

    pub request_buffer: Vec<u8>,
    pub response_buffer: Vec<u8>,
}

impl DNSState {

    pub fn new() -> DNSState {
        return DNSState{
            tx_id: 0,
            transactions: Vec::new(),
            de_state_count: 0,
            events: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
        };
    }

    /// Allocate a new state with capacites in the buffers for
    /// potentially buffering as might be needed in TCP.
    pub fn new_tcp() -> DNSState {
        return DNSState{
            tx_id: 0,
            transactions: Vec::new(),
            de_state_count: 0,
            events: 0,
            request_buffer: Vec::with_capacity(0xffff),
            response_buffer: Vec::with_capacity(0xffff),
        };
    }

    pub fn free(&mut self) {
        SCLogDebug!("Freeing {} transactions left in state.",
                    self.transactions.len());
        while self.transactions.len() > 0 {
            self.free_tx_at_index(0);
        }
        assert!(self.transactions.len() == 0);
    }

    pub fn new_tx(&mut self) -> DNSTransaction {
        let mut tx = DNSTransaction::new();
        self.tx_id += 1;
        tx.id = self.tx_id;
        return tx;
    }

    pub fn free_tx(&mut self, tx_id: u64) {
        SCLogDebug!("************** Freeing TX with ID {}", tx_id);
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.free_tx_at_index(index);
        }
    }

    fn free_tx_at_index(&mut self, index: usize) {
        let tx = self.transactions.remove(index);
        match tx.de_state {
            Some(state) => {
                core::sc_detect_engine_state_free(state);
                self.de_state_count -= 1;
            }
            _ => {}
        }
    }

    // Purges all transactions except one. This is a stateless parser
    // so we don't need to hang onto old transactions.
    //
    // This is to actually handle an edge case where a DNS flood
    // occurs in a single direction with no response packets. In such
    // a case the functions to free a transaction are never called by
    // the app-layer as they require bidirectional traffic.
    pub fn purge(&mut self, tx_id: u64) {
        while self.transactions.len() > MAX_TRANSACTIONS {
            if self.transactions[0].id == tx_id + 1 {
                return;
            }
            SCLogDebug!("Purging DNS TX with ID {}", self.transactions[0].id);
            self.free_tx_at_index(0);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&DNSTransaction> {
        SCLogDebug!("get_tx: tx_id={}", tx_id);
        self.purge(tx_id);
        for tx in &mut self.transactions {
            if tx.id == tx_id + 1 {
                SCLogDebug!("Found DNS TX with ID {}", tx_id);
                return Some(tx);
            }
        }
        SCLogDebug!("Failed to find DNS TX with ID {}", tx_id);
        return None;
    }

    /// Set an event. The event is set on the most recent transaction.
    pub fn set_event(&mut self, event: DNSEvent) {
        let len = self.transactions.len();
        if len == 0 {
            return;
        }

        let mut tx = &mut self.transactions[len - 1];
        core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events,
                                                        event as u8);
        self.events += 1;
    }

    pub fn parse_request(&mut self, input: &[u8]) -> bool {
        match parser::dns_parse_request(input) {
            nom::IResult::Done(_, request) => {
                if request.header.flags & 0x8000 != 0 {
                    SCLogDebug!("DNS message is not a request");
                    self.set_event(DNSEvent::NotRequest);
                    return false;
                }

                if request.header.flags & 0x0040 != 0 {
                    SCLogDebug!("Z-flag set on DNS response");
                    self.set_event(DNSEvent::ZFlagSet);
                    return false;
                }

                let mut tx = self.new_tx();
                tx.request = Some(request);
                self.transactions.push(tx);
                return true;
            }
            nom::IResult::Incomplete(_) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing DNS request");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
            nom::IResult::Error(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing DNS request");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
        }
    }

    pub fn parse_response(&mut self, input: &[u8]) -> bool {
        match parser::dns_parse_response(input) {
            nom::IResult::Done(_, response) => {

                SCLogDebug!("Response header flags: {}", response.header.flags);

                if response.header.flags & 0x8000 == 0 {
                    SCLogDebug!("DNS message is not a response");
                    self.set_event(DNSEvent::NotResponse);
                }

                if response.header.flags & 0x0040 != 0 {
                    SCLogDebug!("Z-flag set on DNS response");
                    self.set_event(DNSEvent::ZFlagSet);
                    return false;
                }

                let mut tx = self.new_tx();
                tx.response = Some(response);
                self.transactions.push(tx);
                return true;
            }
            nom::IResult::Incomplete(_) => {
                // Insufficient data.
                SCLogDebug!("Insufficient data while parsing DNS response");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
            nom::IResult::Error(_) => {
                // Error, probably malformed data.
                SCLogDebug!("An error occurred while parsing DNS response");
                self.set_event(DNSEvent::MalformedData);
                return false;
            }
        }
    }

    /// TCP variation of response request parser to handle the length
    /// prefix as well as buffering.
    ///
    /// Always buffer and read from the buffer. Should optimize to skip
    /// the buffer if not needed.
    pub fn parse_request_tcp(&mut self, input: &[u8]) -> i8 {
        self.request_buffer.extend_from_slice(input);

        while self.request_buffer.len() > 0 {
            let size = match nom::be_u16(&self.request_buffer) {
                nom::IResult::Done(_, len) => {
                    len as usize
                }
                _ => 0 as usize
            };
            SCLogDebug!("Have {} bytes, need {} to parse",
                        self.request_buffer.len(), size);
            if size > 0 && self.request_buffer.len() >= size {
                let msg: Vec<u8> = self.request_buffer.drain(0..(size + 2))
                    .collect();
                if self.parse_request(&msg[2..]) {
                    continue;
                }
                return -1;
            }
            SCLogDebug!("Not enough DNS traffic to parse.");
            return 0;
        }
        return 0;
    }

    /// TCP variation of the response parser to handle the length
    /// prefix as well as buffering.
    ///
    /// Always buffer and read from the buffer. Should optimize to skip
    /// the buffer if not needed.
    pub fn parse_response_tcp(&mut self, input: &[u8]) -> i8 {
        self.response_buffer.extend_from_slice(input);
        let size = match nom::be_u16(&self.response_buffer) {
            nom::IResult::Done(_, len) => {
                len as usize
            }
            _ => 0 as usize
        };
        if size > 0 && self.response_buffer.len() + 2 >= size {
            let msg: Vec<u8> = self.response_buffer.drain(0..(size + 2))
                .collect();
            if self.parse_response(&msg[2..]) {
                return 1;
            }
            return -1;
        }
        0
    }
}

/// Declare DNSState as a generic parser
impl RParser for DNSState {
    fn parse_to_server(&mut self, _f: core::Flow, i: &[u8], _d:u8) -> u32 {
        self.parse_request_tcp(i) as u32
    }

    fn parse_to_client(&mut self, _f: core::Flow, i: &[u8], _d:u8) -> u32 {
        self.parse_response_tcp(i) as u32
    }
}

/// Implement Drop for DNSState as transactions need to do some
/// explicit cleanup.
impl Drop for DNSState {
    fn drop(&mut self) {
        self.free();
    }
}

/// Returns *mut DNSState
#[no_mangle]
pub extern "C" fn rs_dns_state_new() -> *mut libc::c_void {
    let state = DNSState::new();
    r_wrap_state_return!(DNSState,state)
}

/// Returns *mut DNSState
#[no_mangle]
pub extern "C" fn rs_dns_state_tcp_new() -> *mut libc::c_void {
    let state = DNSState::new_tcp();
    r_wrap_state_return!(DNSState,state)
}

r_declare_state_free!(rs_dns_state_free,DNSState);

#[no_mangle]
pub extern "C" fn rs_dns_state_tx_free(state: &mut DNSState,
                                       tx_id: libc::uint64_t)
{
    state.free_tx(tx_id);
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_dns_parse_request(_flow: *mut core::Flow,
                                       state: &mut DNSState,
                                       _pstate: *mut libc::c_void,
                                       input: *mut libc::uint8_t,
                                       input_len: libc::uint32_t,
                                       _data: *mut libc::c_void)
                                       -> libc::int8_t {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    if state.parse_request(buf) {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_parse_response(_flow: *mut core::Flow,
                                        state: &mut DNSState,
                                        _pstate: *mut libc::c_void,
                                        input: *mut libc::uint8_t,
                                        input_len: libc::uint32_t,
                                        _data: *mut libc::c_void)
                                        -> libc::int8_t {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    if state.parse_response(buf) {
        1
    } else {
        -1
    }
}

/// C binding parse a DNS request. Returns 1 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rs_dns_parse_request_tcp(_flow: *mut core::Flow,
                                           state: &mut DNSState,
                                           _pstate: *mut libc::c_void,
                                           input: *mut libc::uint8_t,
                                           input_len: libc::uint32_t,
                                           _data: *mut libc::c_void)
                                           -> libc::int8_t {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    return state.parse_request_tcp(buf);
}

#[no_mangle]
pub extern "C" fn rs_dns_parse_response_tcp(_flow: *mut core::Flow,
                                            state: &mut DNSState,
                                            _pstate: *mut libc::c_void,
                                            input: *mut libc::uint8_t,
                                            input_len: libc::uint32_t,
                                            _data: *mut libc::c_void)
                                            -> libc::int8_t {
    let buf = unsafe{std::slice::from_raw_parts(input, input_len as usize)};
    return state.parse_response_tcp(buf);
}

#[no_mangle]
pub extern "C" fn rs_dns_state_progress_completion_status(
    _direction: libc::uint8_t)
    -> libc::c_int
{
    SCLogDebug!("rs_dns_state_progress_completion_status");
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_alstate_progress(_tx: &mut DNSTransaction,
                                                 _direction: libc::uint8_t)
                                                 -> libc::uint8_t
{
    // This is a stateless parser, just the existence of a transaction
    // means its complete.
    SCLogDebug!("rs_dns_tx_get_alstate_progress");
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_set_logged(_state: &mut DNSState,
                                       tx: &mut DNSTransaction,
                                       logger: libc::uint32_t)
{
    tx.logged.set_logged(logger);
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_logged(_state: &mut DNSState,
                                       tx: &mut DNSTransaction,
                                       logger: libc::uint32_t)
                                       -> i8
{
    if tx.logged.is_logged(logger) {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_tx_count(state: &mut DNSState)
                                            -> libc::uint64_t
{
    SCLogDebug!("rs_dns_state_get_tx_count: returning {}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_tx(state: &mut DNSState,
                                      tx_id: libc::uint64_t)
                                      -> *mut DNSTransaction
{
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe{transmute(tx)};
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_state_has_detect_state(state: &mut DNSState) -> u8
{
    if state.de_state_count > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_set_tx_detect_state(
    state: &mut DNSState,
    tx: &mut DNSTransaction,
    de_state: &mut core::DetectEngineState)
{
    state.de_state_count += 1;
    tx.de_state = Some(de_state);
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_tx_detect_state(
    tx: &mut DNSTransaction)
    -> *mut core::DetectEngineState
{
    match tx.de_state {
        Some(ds) => {
            return ds;
        },
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_state_has_events(state: &mut DNSState) -> u8 {
    if state.events > 0 {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_state_get_events(state: &mut DNSState,
                                          tx_id: libc::uint64_t)
                                          -> *mut core::AppLayerDecoderEvents
{
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx.events;
        }
        _ => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_query_name(tx: &mut DNSTransaction,
                                       i: libc::uint16_t,
                                       buf: *mut *const libc::uint8_t,
                                       len: *mut libc::uint32_t)
                                       -> libc::uint8_t
{
    for request in &tx.request {
        if (i as usize) < request.queries.len() {
            let query = &request.queries[i as usize];
            if query.name.len() > 0 {
                unsafe {
                    *len = query.name.len() as libc::uint32_t;
                    *buf = query.name.as_ptr();
                }
                return 1;
            }
        }
    }
    return 0;
}

/// Get the DNS transaction ID of a transaction.
//
/// extern uint16_t rs_dns_tx_get_tx_id(RSDNSTransaction *);
#[no_mangle]
pub extern "C" fn rs_dns_tx_get_tx_id(tx: &mut DNSTransaction) -> libc::uint16_t
{
    return tx.tx_id()
}

/// Get the DNS response flags for a transaction.
///
/// extern uint16_t rs_dns_tx_get_response_flags(RSDNSTransaction *);
#[no_mangle]
pub extern "C" fn rs_dns_tx_get_response_flags(tx: &mut DNSTransaction)
                                           -> libc::uint16_t
{
    return tx.rcode();
}

#[no_mangle]
pub extern "C" fn rs_dns_tx_get_query_rrtype(tx: &mut DNSTransaction,
                                         i: libc::uint16_t,
                                         rrtype: *mut libc::uint16_t)
                                         -> libc::uint8_t
{
    for request in &tx.request {
        if (i as usize) < request.queries.len() {
            let query = &request.queries[i as usize];
            if query.name.len() > 0 {
                unsafe {
                    *rrtype = query.rrtype;
                }
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_probe(input: *const libc::uint8_t, len: libc::uint32_t)
                               -> libc::uint8_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    match parser::dns_parse_request(slice) {
        nom::IResult::Done(_, _) => {
            return 1;
        }
        _ => {
            return 0;
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_dns_probe_tcp(input: *const libc::uint8_t,
                                   len: libc::uint32_t,
                                   _offset: *const libc::uint32_t)
                                   -> libc::uint16_t
{
    let slice: &[u8] = unsafe {
        std::slice::from_raw_parts(input as *mut u8, len as usize)
    };
    match nom::be_u16(slice) {
        nom::IResult::Done(rem, len) => {
            if rem.len() >= len as usize {
                match parser::dns_parse_request(rem) {
                    nom::IResult::Done(_, _) => {
                        return *ALPROTO_DNS;
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    return 0;
}

#[cfg(test)]
mod tests {

    // Playing with vector draining...
    #[test]
    fn test_drain() {
        let buf: &[u8] = &[
            0x09, 0x63,
            0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x66,
            0x07, 0x64, 0x72, 0x6f, 0x70, 0x62, 0x6f, 0x78,
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        ];
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(buf);
        assert_eq!(v.len(), buf.len());

        // Drain one byte.
        let drained: Vec<u8> = v.drain(0..1).collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(v.len(), buf.len() - 1);
        assert_eq!(buf[0], drained[0]);

        // Drain some more.
        v.drain(0..8);
        assert_eq!(v.len(), buf.len() - 9);
    }
}
