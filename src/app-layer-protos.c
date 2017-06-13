/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#include "suricata-common.h"
#include "app-layer-protos.h"

#include "util-unittest.h"

#define CASE_CODE(E)  case E: return #E

struct AppProtoWithName {
    AppProto     id;
    const char * name;
};

// keep order same as in app-layer-protos.h
const struct AppProtoWithName AlProtoRegistry[] = {
    { ALPROTO_UNKNOWN,  "unknown" },
    { ALPROTO_HTTP,     "http" },
    { ALPROTO_FTP,      "ftp" },
    { ALPROTO_SMTP,     "smtp" },
    { ALPROTO_TLS,      "tls" },
    { ALPROTO_SSH,      "ssh" },
    { ALPROTO_IMAP,     "imap" },
    { ALPROTO_MSN,      "msn" },
    { ALPROTO_JABBER,   "jabber" },
    { ALPROTO_SMB,      "smb" },
    { ALPROTO_SMB2,     "smb2" },
    { ALPROTO_DCERPC,   "dcerpc" },
    { ALPROTO_IRC,      "irc" },
    { ALPROTO_DNS,      "dns" },
    { ALPROTO_MODBUS,   "modbus" },
    { ALPROTO_ENIP,     "enip" },
    { ALPROTO_DNP3,     "dnp3" },
    { ALPROTO_NFS3,     "nfs3" },
    { ALPROTO_TEMPLATE, "template" },
    { ALPROTO_FAILED,   "failed" },
#ifdef UNITTESTS
    { ALPROTO_TEST,     "test" },
#endif
};

const char *AppProtoToString(AppProto alproto)
{
    if (alproto >= ALPROTO_MAX)
        return NULL;
    return AlProtoRegistry[alproto].name;
}

AppProto StringToAppProto(const char *proto)
{
    int i;

    if (proto == NULL)
        return ALPROTO_UNKNOWN;

    for (i=0; i<ALPROTO_MAX; i++) {
        if (strcmp(AlProtoRegistry[i].name, proto)==0)
            return AlProtoRegistry[i].id;
    }

    return ALPROTO_UNKNOWN;
}

/* TESTS */
#ifdef UNITTESTS
static int AppProtoTest01 (void)
{
    int i;

    if ( (sizeof(AlProtoRegistry)/sizeof(struct AppProtoWithName)) != ALPROTO_MAX ) {
        printf("AlProtoRegistry size does not match enum size\n");
        return 0;
    }

    for (i=0; i<ALPROTO_MAX; i++) {
        if (i != AlProtoRegistry[i].id) {
            printf("AlProto id %d does not match registry entry ID %d\n",
                    i,
                    AlProtoRegistry[i].id);
            return 0;
        }
    }
    return 1;
}

static int AppProtoTest02 (void)
{
    AppProto alproto = ALPROTO_SMTP;
    const char * proto = AppProtoToString(alproto);

    if (proto == NULL || strcmp(proto,"smtp")!=0)
        return 0;

    return 1;
}

static int AppProtoTest03 (void)
{
    const char * proto = "smtp";
    AppProto alproto = StringToAppProto(proto);

    if (alproto != ALPROTO_SMTP)
        return 0;

    return 1;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for AppProto
 */
void AppProtoRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
/* matching */
    UtRegisterTest("AppProtoTest01", AppProtoTest01);
    UtRegisterTest("AppProtoTest02", AppProtoTest02);
    UtRegisterTest("AppProtoTest03", AppProtoTest03);
#endif /* UNITTESTS */
}
