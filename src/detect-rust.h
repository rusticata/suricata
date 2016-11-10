/* Copyright (C) 2015 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 */

#ifndef __DETECT_RUST_H__
#define __DETECT_RUST_H__

#include "rusticata.h"

/** Per keyword data. This is set up by the DetectRustSetup() function.
 *  Each signature will have an instance of DetectRustData per occurence
 *  of the keyword.
 *  The structure should be considered static/readonly after initialization.
 */
typedef struct DetectRustData_ {
    uint32_t cipher_id;
    uint32_t kx_bits;
    enum TlsCipherKx kx;
    uint8_t arg1;
    uint8_t arg2;
} DetectRustData;

/** \brief registers the keyword into the engine. Called from
 *         detect.c::SigTableSetup() */
void DetectRustRegister(void);

#endif /* __DETECT_RUST_H__ */
