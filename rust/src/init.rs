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
 *
 * Author(s): Pierre Chifflier <chifflier@wzdftpd.net>
 *
 */

extern crate libc;
use libc::{c_void,uint8_t};

use std;
use core;
use rparser::RParser;

use dns::dns::DnsTCPParser;


/// Rusticata crate init function
///
/// This function **must** be called by the client application (Suricata) to initialize the
/// rusticata library functions.
///
/// The argument is a pointer to a configuration structure, containing a magic number,
/// a pointer to the C log function, and the log level of the client application.
/// Rusticata will use the same log level, and configure a Rust Logger object to send logs
/// to Suricata.
///
/// The lifetime of the configuration **must** be greater or equal to the one of the
/// rusticata crate.
#[no_mangle]
pub extern "C" fn rusticata_init(config: * mut c_void) -> i32 {
    assert!(std::ptr::null_mut() != config);

    // let _ = RustParser::new(
    //     "rust-ssh", 6, "22", 0,
    //     unsafe{ &mut dns::ALPROTO_DNS },
    //     std::ptr::null(),
    //     rs_dns_probe_tcp, r_generic_parse,
    //     rs_dns_state_tcp_new, rs_dns_state_free
    //     );

    0
}


/// Returns the nth parser, or NULL
#[no_mangle]
pub extern "C" fn rusticata_get_parser(index: u32) -> *const c_void {
    // match HASHMAP.values().nth(index as usize) {
    //     Some(parser) => {
    //         match parser.c_parser {
    //             Some(ref cp) => cp as *const _ as *const c_void,
    //             None         => std::ptr::null(),
    //         }
    //     },
    //     None         => std::ptr::null(),
    // }

    match index {
        0 => &DnsTCPParser.c_parser as *const _ as *const c_void,
        _ => std::ptr::null(),
    }
}


#[no_mangle]
pub extern "C" fn r_generic_parse(flow: core::Flow, direction: u8, input: *const uint8_t, input_len: u32, raw_ptr: *mut c_void) -> u32 {
    let ptr = raw_ptr as *mut Box<RParser>;
    let data_len = input_len as usize;
    let data : &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, data_len) };
    if ptr.is_null() { return 0xffff; };
    let ptr_typed = ptr as *mut Box<RParser>;
    let parser = unsafe { &mut *ptr_typed };
    if direction == 0 { parser.parse_to_server(flow, data, direction) }
    else { parser.parse_to_client(flow, data, direction) }
}

#[no_mangle]
pub extern "C" fn r_get_next_event(raw_ptr: *mut c_void) -> u32 {
    let ptr = raw_ptr as *mut Box<RParser>;
    if ptr.is_null() { return 0xffff; };
    let ptr_typed = ptr as *mut Box<RParser>;
    let parser = unsafe { &mut *ptr_typed };
    parser.get_next_event()
}

