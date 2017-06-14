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

use libc;
use core;

/// Interface of all Rusticata parsers.
///
/// A object implementing the RParser trait is an instance of a parser,
/// including the state (and all associated variables).
pub trait RParser {
    /// Parsing function
    ///
    /// This function is called for every packet of a connection.
    ///
    /// Arguments:
    ///
    /// - `self`: the state (parser instance)
    /// - The `Flow` object
    /// - a slice on the packet data
    /// - the direction of this packet (0: to server, 1: to client)
    ///
    /// Return value:
    ///
    /// `R_STATUS_OK` or `R_STATUS_FAIL`, possibly or'ed with
    /// `R_STATUS_EVENTS` if parsing events were raised.
    fn parse_to_server(&mut self, core::Flow, &[u8], u8) -> u32;

    fn parse_to_client(&mut self, core::Flow, &[u8], u8) -> u32;

    /// Get next event
    ///
    /// This function is called to get the next event (consuming it) if `parse`
    /// returned `R_STATUS_EVENTS`.
    ///
    /// Returns the next event, or 0xffffffff if there are no more events.
    fn get_next_event(&mut self) -> u32 {
        R_NO_MORE_EVENTS
    }
}


#[repr(C)]
pub struct StaticCString(pub *const u8);
unsafe impl Sync for StaticCString {}


#[repr(C)]
pub struct MyEvent {
    pub name:  StaticCString,
    pub value: libc::c_int,
}

#[macro_export]
macro_rules! r_event {
    ($name:expr, $value:expr) => { MyEvent{ name:StaticCString($name as *const u8), value: $value } }
}

// status: return code, events

pub static R_STATUS_EVENTS : u32  = 0x0100;

pub static R_STATUS_OK : u32      = 0x0000;
pub static R_STATUS_FAIL : u32    = 0x0001;

pub static R_STATUS_EV_MASK : u32 = 0x0f00;
pub static R_STATUS_MASK : u32    = 0x00ff;

pub const R_NO_MORE_EVENTS : u32  = ::std::u32::MAX;

#[macro_export]
macro_rules! r_status_is_ok {
    ($status:expr) => { ($status & $crate::R_STATUS_MASK) == $crate::R_STATUS_MASK }
}

#[macro_export]
macro_rules! r_status_has_events {
    ($status:expr) => { ($status & $crate::R_STATUS_EV_MASK) == $crate::R_STATUS_EVENTS }
}

// Helper macros
// We can't define them (can we ?) in the trait, partly because of the 'no_mangle' and 'extern'
// stuff.
// This forces to use macros in addition to the trait, but at least provides a proper way of
// encapsulating the translation of C variables to rust.

// Double-box, because we are wrapping the RParser trait, and a Box<Trait> has the size of two
// pointers (128 bits) so cannot be caster to a single pointer.
// See http://stackoverflow.com/questions/33929079/rust-ffi-passing-trait-object-as-context-to-call-callbacks-on
#[macro_export]
macro_rules! r_declare_state_new {
    ($f:ident, $ty:ident, $args:expr) => {
        #[no_mangle]
        pub extern "C" fn $f() -> *mut libc::c_void {
            let tmp: Box<Box<RParser>> = Box::new(Box::new($ty::new($args)));
            Box::into_raw(tmp) as *mut Box<RParser> as *mut libc::c_void
        }
    }
}

#[macro_export]
macro_rules! r_wrap_state_return {
    ($ty:ident, $e:expr) => {
        {
            let tmp: Box<Box<RParser>> = Box::new(Box::new($e));
            Box::into_raw(tmp) as *mut Box<RParser> as *mut libc::c_void
        }
    }
}

#[macro_export]
macro_rules! r_declare_state_free {
    ($f:ident, $ty:ident) => {
        #[no_mangle]
        pub extern fn $f(ptr: *mut libc::c_void)
        {
            let b: Box<Box<$ty>> = unsafe { ::std::mem::transmute(ptr) };
            // reference will be dropped automatically, and allocated memory
            // will be freed
            // but let's do it explicitly
            drop(b);
        }
    }
}





/// Register probing parser
///
/// The probing parser must return a valid ALPROTO value, defined in `app-layer-protos.h`
#[macro_export]
macro_rules! r_implement_probe {
    ($f:ident, $g:ident, $alproto:ident) => {
        pub static mut $alproto : u16 = 0xffff;

        #[no_mangle]
        pub extern "C" fn $f(input: *const c_char, input_len: u32, _offset: *const c_char) -> u16 {
            let data_len = input_len as usize;
            let data : &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, data_len) };
            let r = match $g(data) {
                true  => unsafe{ $alproto },
                false => 0,
            };
            info!("probe: recognized as {}", r);
            r
        }
    }
}
