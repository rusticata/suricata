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
use libc::{c_void,c_char,uint8_t,uint32_t};
use std::ffi::CString;

pub type ProbeFn      = extern "C" fn (*const uint8_t, u32, *const uint32_t) -> u16;
pub type ParseFn      = extern "C" fn (u8, *const uint8_t, u32, *mut c_void) -> u32;
pub type NewStateFn   = extern "C" fn () -> *mut c_void;
pub type FreeStateFn  = extern "C" fn (*mut c_void) -> ();

pub struct RustParser {
    /// Protocol name.
    pub name:         CString,
    /// Default port
    pub default_port: CString,

    /// The structure exposed to the C code
    pub c_parser:     Option<RustCParser>,
}

#[repr(C)]
pub struct RustCParser {
    /// Protocol name. Must be \0-terminated
    pub name:         *const c_char,
    pub ip_proto:     u16,
    pub default_port: *const c_char,
    pub min_frame_length: i32,
    /// Application layer protocol ID
    pub al_proto:     u16,
    /// Events table
    pub events:       *const c_void,
    pub probe:        ProbeFn,
    pub new_state:    NewStateFn,
    pub free_state:   FreeStateFn,
}

/// Declare RustCParser as shareable between threads.
/// This is only true because we only use read-only instances, but is necessary to initialize
/// the global registry and send structures to the C code.
unsafe impl Sync for RustCParser { }

extern {
    pub fn StringToAppProto(proto: *const uint8_t) -> u16;
}

impl RustParser {
    pub fn new(name: &str, proto: u16, default_port: &str, min_frame_length: i32,
               al_proto: u16,
               events: *const c_void,
               probe: ProbeFn,
               new: NewStateFn, free: FreeStateFn)
            -> RustParser {
        let r = RustParser{
            name:         CString::new(name).unwrap(),
            default_port: CString::new(default_port).unwrap(),
            c_parser:     None,
        };
        // println!("Registered alproto {} returned {}", name, al_proto);
        RustParser{
            c_parser: Some(
                          RustCParser{
                              name:         r.name.as_ptr(),
                              ip_proto:     proto,
                              default_port: r.default_port.as_ptr(),
                              min_frame_length: min_frame_length,
                              al_proto:     al_proto,
                              events:       events,
                              probe:        probe,
                              new_state:    new,
                              free_state:   free,
                          }
                          ),
            .. r
        }
    }

    pub fn al_proto(&self) -> u16 {
        self.c_parser.as_ref().unwrap().al_proto
    }
}

