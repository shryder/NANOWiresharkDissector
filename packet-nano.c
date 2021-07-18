/* packet-nano.c
* Routines for Nano / RaiBlocks dissection
* Copyright 2018, Roland Haenel <roland@haenel.me>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/

/*
* For information about Nano / RaiBlocks, go to http://www.nano.org
*/

#include <config.h>

#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/proto_data.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <wsutil/str_util.h>

void proto_reg_handoff_nano(void);
void proto_register_nano(void);

static dissector_handle_t nano_tcp_handle;

static int proto_nano = -1;

static int hf_nano_magic_number = -1;
static int hf_nano_version_max = -1;
static int hf_nano_version_using = -1;
static int hf_nano_version_min = -1;
static int hf_nano_packet_type = -1;
static int hf_nano_extensions = -1;
static int hf_nano_extensions_block_type = -1;
static int hf_nano_keepalive_peer_ip = -1;
static int hf_nano_keepalive_peer_port = -1;

static int hf_nano_block_hash_previous = -1;
static int hf_nano_block_hash_source = -1;
static int hf_nano_block_signature = -1;
static int hf_nano_block_work = -1;
static int hf_nano_block_destination_account = -1;
static int hf_nano_block_balance = -1;
static int hf_nano_block_account = -1;
static int hf_nano_block_representative_account = -1;
static int hf_nano_block_link = -1;

static int hf_nano_vote_account = -1;
static int hf_nano_vote_signature = -1;
static int hf_nano_vote_sequence = -1;

static int hf_nano_bulk_pull_account = -1;
static int hf_nano_bulk_pull_block_hash_end = -1;

static int hf_nano_bulk_pull_blocks_min_hash = -1;
static int hf_nano_bulk_pull_blocks_max_hash = -1;
static int hf_nano_bulk_pull_blocks_mode = -1;
static int hf_nano_bulk_pull_blocks_max_count = -1;

static int hf_nano_bulk_push_block_type = -1;

static int hf_nano_bulk_pull_block_type = -1;

static gint ett_nano = -1;
static gint ett_nano_header = -1;
static gint ett_nano_extensions = -1;
static gint ett_nano_peers = -1;
static gint ett_nano_peer_details = -1;
static gint ett_nano_block = -1;
static gint ett_nano_vote = -1;
static gint ett_nano_bulk_pull = -1;
static gint ett_nano_bulk_pull_response = -1;
static gint ett_nano_frontier_req = -1;
static gint ett_nano_frontier_response = -1;
static gint ett_nano_bulk_pull_blocks = -1;
static gint ett_nano_hash_pair = -1;
static gint ett_nano_bulk_pull_account = -1;
static gint ett_nano_vote_common = -1;
static gint ett_nano_confirm_ack_hashes = -1;
static gint ett_nano_confirm_ack = -1;

#define NANO_PACKET_TYPE_INVALID 0
#define NANO_PACKET_TYPE_NOT_A_TYPE 1
#define NANO_PACKET_TYPE_KEEPALIVE 2
#define NANO_PACKET_TYPE_PUBLISH 3
#define NANO_PACKET_TYPE_CONFIRM_REQ 4
#define NANO_PACKET_TYPE_CONFIRM_ACK 5
#define NANO_PACKET_TYPE_BULK_PULL 6
#define NANO_PACKET_TYPE_BULK_PUSH 7
#define NANO_PACKET_TYPE_FRONTIER_REQ 8
#define NANO_PACKET_TYPE_BULK_PULL_BLOCKS 9
#define NANO_PACKET_TYPE_NODE_ID_HANDSHAKE 10
#define NANO_PACKET_TYPE_BULK_PULL_ACCOUNT 11
#define NANO_PACKET_TYPE_TELEMETRY_REQ 12
#define NANO_PACKET_TYPE_TELEMETRY_ACK 13

static const value_string nano_packet_type_strings[] = {
    { NANO_PACKET_TYPE_INVALID, "Invalid" },
    { NANO_PACKET_TYPE_NOT_A_TYPE, "Not A Type" },
    { NANO_PACKET_TYPE_KEEPALIVE, "Keepalive" },
    { NANO_PACKET_TYPE_PUBLISH, "Publish" },
    { NANO_PACKET_TYPE_CONFIRM_REQ, "Confirm Req" },
    { NANO_PACKET_TYPE_CONFIRM_ACK, "Confirm Ack" },
    { NANO_PACKET_TYPE_BULK_PULL, "Bulk Pull" },
    { NANO_PACKET_TYPE_BULK_PUSH, "Bulk Push" },
    { NANO_PACKET_TYPE_FRONTIER_REQ, "Frontier Req" },
    { NANO_PACKET_TYPE_BULK_PULL_BLOCKS, "Bulk Pull Blocks" },
    { NANO_PACKET_TYPE_NODE_ID_HANDSHAKE, "Node ID Handshake" },
    { NANO_PACKET_TYPE_BULK_PULL_ACCOUNT, "Bulk Pull Account" },
    { NANO_PACKET_TYPE_TELEMETRY_REQ, "Telemetry Req" },
    { NANO_PACKET_TYPE_TELEMETRY_ACK, "Telemetry Ack" },
    { 0, NULL },
};

#define NANO_BLOCK_TYPE_INVALID 0
#define NANO_BLOCK_TYPE_NOT_A_BLOCK 1
#define NANO_BLOCK_TYPE_SEND 2
#define NANO_BLOCK_TYPE_RECEIVE 3
#define NANO_BLOCK_TYPE_OPEN 4
#define NANO_BLOCK_TYPE_CHANGE 5
#define NANO_BLOCK_TYPE_STATE 6

static const value_string nano_block_type_strings[] = {
    { NANO_BLOCK_TYPE_INVALID, "Invalid" },
    { NANO_BLOCK_TYPE_NOT_A_BLOCK, "Not A Block" },
    { NANO_BLOCK_TYPE_SEND, "Send" },
    { NANO_BLOCK_TYPE_RECEIVE, "Receive" },
    { NANO_BLOCK_TYPE_OPEN, "Open" },
    { NANO_BLOCK_TYPE_CHANGE, "Change" },
    { NANO_BLOCK_TYPE_STATE, "State" },
    { 0, NULL },
};

static const string_string nano_magic_numbers[] = {
    { "RA", "Nano Dev Network" },
    { "RB", "Nano Beta Network" },
    { "RC", "Nano Live Network" },
    { "RX", "Nano Test Network" },
    { 0, NULL }
};

#define NANO_BULK_PULL_BLOCKS_MODE_LIST_BLOCKS 0
#define NANO_BULK_PULL_BLOCKS_MODE_CHECKSUM_BLOCKS 1

static const value_string nano_bulk_pull_blocks_mode_strings[] = {
    { NANO_BULK_PULL_BLOCKS_MODE_LIST_BLOCKS, "List Blocks" },
    { NANO_BULK_PULL_BLOCKS_MODE_CHECKSUM_BLOCKS, "Checksum Blocks" },
    { 0, NULL },
};

#define NANO_TCP_PORT 17075 /* Not IANA registered */

#define NANO_BLOCK_SIZE_SEND    (32+32+16+64+8)
#define NANO_BLOCK_SIZE_RECEIVE (32+32+64+8)
#define NANO_BLOCK_SIZE_OPEN    (32+32+32+64+8)
#define NANO_BLOCK_SIZE_CHANGE  (32+32+64+8)
#define NANO_BLOCK_SIZE_STATE   (32+32+32+16+32+64+8)

// Nano header length
#define NANO_HEADER_LENGTH 8

struct nano_session_state {
    int client_packet_type;
    guint32 server_port;
};

void append_info_col(column_info *cinfo, const gchar *format, ...) {
    va_list ap;

    va_start(ap, format);
    col_append_sep_fstr(cinfo, COL_INFO, " | ", format, ap);
    va_end(ap);
}

//
// Dissect Blocks
//
static int dissect_nano_block (int block_type, tvbuff_t* tvb, proto_tree* tree, int offset) {
    switch (block_type) {
        case NANO_BLOCK_TYPE_RECEIVE:
            return dissect_nano_receive_block(tvb, tree, offset);
        case NANO_BLOCK_TYPE_OPEN:
            return dissect_nano_open_block(tvb, tree, offset);
        case NANO_BLOCK_TYPE_SEND:
            return dissect_nano_send_block(tvb, tree, offset);
        case NANO_BLOCK_TYPE_STATE:
            return dissect_nano_state(tvb, tree, offset);
        case NANO_BLOCK_TYPE_CHANGE:
            return dissect_nano_change_block(tvb, tree, offset);
    }

    return 0;
}

static int dissect_nano_receive_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset) {
    proto_tree *block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_RECEIVE, ett_nano_block, NULL, "Receive Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_hash_source, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int dissect_nano_send_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset) {
    proto_tree *block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_SEND, ett_nano_block, NULL, "Send Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_destination_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_balance, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int dissect_nano_open_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset) {
    proto_tree *block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_OPEN, ett_nano_block, NULL, "Open Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_source, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_representative_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int dissect_nano_change_block(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_CHANGE, ett_nano_block, NULL, "Change Block");

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_representative_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int dissect_nano_state(tvbuff_t *tvb, proto_tree *nano_tree, int offset)
{
    proto_tree *block_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_BLOCK_SIZE_STATE, ett_nano_block, NULL, "State Block");

    proto_tree_add_item(block_tree, hf_nano_block_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_hash_previous, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_representative_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_balance, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(block_tree, hf_nano_block_link, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(block_tree, hf_nano_block_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(block_tree, hf_nano_block_work, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int get_block_type_size (int block_type) {
    switch (block_type) {
        case NANO_BLOCK_TYPE_RECEIVE:
            return NANO_BLOCK_SIZE_RECEIVE;
        case NANO_BLOCK_TYPE_OPEN:
            return NANO_BLOCK_SIZE_OPEN;
        case NANO_BLOCK_TYPE_SEND:
            return NANO_BLOCK_SIZE_SEND;
        case NANO_BLOCK_TYPE_STATE:
            return NANO_BLOCK_SIZE_STATE;
        case NANO_BLOCK_TYPE_CHANGE:
            return NANO_BLOCK_SIZE_CHANGE;
    }

    return 0;
}
//
// Dissect Keepalive
//
static const char fast_strings[][4] = {
    "0", "1", "2", "3", "4", "5", "6", "7",
    "8", "9", "10", "11", "12", "13", "14", "15",
    "16", "17", "18", "19", "20", "21", "22", "23",
    "24", "25", "26", "27", "28", "29", "30", "31",
    "32", "33", "34", "35", "36", "37", "38", "39",
    "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "50", "51", "52", "53", "54", "55",
    "56", "57", "58", "59", "60", "61", "62", "63",
    "64", "65", "66", "67", "68", "69", "70", "71",
    "72", "73", "74", "75", "76", "77", "78", "79",
    "80", "81", "82", "83", "84", "85", "86", "87",
    "88", "89", "90", "91", "92", "93", "94", "95",
    "96", "97", "98", "99", "100", "101", "102", "103",
    "104", "105", "106", "107", "108", "109", "110", "111",
    "112", "113", "114", "115", "116", "117", "118", "119",
    "120", "121", "122", "123", "124", "125", "126", "127",
    "128", "129", "130", "131", "132", "133", "134", "135",
    "136", "137", "138", "139", "140", "141", "142", "143",
    "144", "145", "146", "147", "148", "149", "150", "151",
    "152", "153", "154", "155", "156", "157", "158", "159",
    "160", "161", "162", "163", "164", "165", "166", "167",
    "168", "169", "170", "171", "172", "173", "174", "175",
    "176", "177", "178", "179", "180", "181", "182", "183",
    "184", "185", "186", "187", "188", "189", "190", "191",
    "192", "193", "194", "195", "196", "197", "198", "199",
    "200", "201", "202", "203", "204", "205", "206", "207",
    "208", "209", "210", "211", "212", "213", "214", "215",
    "216", "217", "218", "219", "220", "221", "222", "223",
    "224", "225", "226", "227", "228", "229", "230", "231",
    "232", "233", "234", "235", "236", "237", "238", "239",
    "240", "241", "242", "243", "244", "245", "246", "247",
    "248", "249", "250", "251", "252", "253", "254", "255"
};

void ip_to_str_buf(const guint8 *ad, gchar *buf, const int buf_len)
{
    register gchar const *p;
    register gchar *b=buf;

    if (buf_len < WS_INET_ADDRSTRLEN) {
        (void) g_strlcpy(buf, "[Buffer too small]", buf_len);  /* Let the unexpected value alert user */
        return;
    }

    p=fast_strings[*ad++];
    do {
        *b++=*p;
        p++;
    } while(*p);
    *b++='.';

    p=fast_strings[*ad++];
    do {
        *b++=*p;
        p++;
    } while(*p);
    *b++='.';

    p=fast_strings[*ad++];
    do {
        *b++=*p;
        p++;
    } while(*p);
    *b++='.';

    p=fast_strings[*ad];
    do {
        *b++=*p;
        p++;
    } while(*p);
    *b=0;
}

int ip6_to_str_buf(const ws_in6_addr *addr, gchar *buf, int buf_size)
{
    gchar addr_buf[WS_INET6_ADDRSTRLEN];
    int len;

    /* slightly more efficient than ip6_to_str_buf_with_pfx(addr, buf, buf_size, NULL) */
    len = (int)g_strlcpy(buf, ws_inet_ntop6(addr, addr_buf, sizeof(addr_buf)), buf_size);     /* this returns len = strlen(addr_buf) */

    if (len > buf_size - 1) { /* size minus nul terminator */
        len = (int)g_strlcpy(buf, "[Buffer too small]", buf_size);  /* Let the unexpected value alert user */
    }
    return len;
}

// dissect the inside of a keepalive packet (that is, the neighbor nodes)
static int dissect_nano_keepalive(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nano_tree, int offset)
{
    proto_item *ti;
    proto_tree *peer_tree, *peer_entry_tree;
    ws_in6_addr ip_addr;
    guint32 port;
    gchar buf[100];

    peer_tree = proto_tree_add_subtree(nano_tree, tvb, offset, 8*(16+2), ett_nano_peers, NULL, "Peer List");

    for (int i = 0; i < 8; i++) {
        peer_entry_tree = proto_tree_add_subtree(peer_tree, tvb, offset, 16 + 2, ett_nano_peer_details, &ti, "Peer");

        tvb_get_ipv6(tvb, offset, &ip_addr);
        proto_tree_add_item(peer_entry_tree, hf_nano_keepalive_peer_ip, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item_ret_uint(peer_entry_tree, hf_nano_keepalive_peer_port, tvb, offset, 2, ENC_LITTLE_ENDIAN, &port);
        offset += 2;

        if (!memcmp(&ip_addr, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 16)) {
            proto_item_append_text(ti, ": (none)");
        } else if (!memcmp(&ip_addr, "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xff\xff", 12)) {
            ip_to_str_buf((gchar *) &ip_addr + 12, buf, sizeof(buf));
            proto_item_append_text(ti, ": %s:%d", buf, port);
        } else {
            ip6_to_str_buf(&ip_addr, buf, sizeof(buf));
            proto_item_append_text(ti, ": [%s]:%d", buf, port);
        }
    }

    append_info_col(pinfo->cinfo, "Keepalive");

    return offset;
}

//
// Dissect Message Header
//
static int dissect_nano_extensions_header() {

}


// Dissect message header
static int dissect_nano_header(tvbuff_t *tvb, proto_tree *nano_tree, int offset, guint *nano_packet_type, guint64 *extensions)
{
    proto_tree *header_tree;
    char *nano_magic_number;
    static int * const nano_extensions[] = {
        &hf_nano_extensions_block_type,
        NULL
    };

    nano_magic_number = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 2, ENC_ASCII);

    header_tree = proto_tree_add_subtree(nano_tree, tvb, offset, NANO_HEADER_LENGTH, ett_nano_header, NULL, "Nano Protocol Header");

    proto_tree_add_string_format_value(header_tree, hf_nano_magic_number, tvb, 0, 2, nano_magic_number, "%s (%s)", str_to_str(nano_magic_number, nano_magic_numbers, "Unknown"), nano_magic_number);
    offset += 2;

    proto_tree_add_item(header_tree, hf_nano_version_max, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_nano_version_using, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_nano_version_min, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item_ret_uint(header_tree, hf_nano_packet_type, tvb, offset, 1, ENC_NA, nano_packet_type);
    offset += 1;

    proto_tree_add_bitmask_ret_uint64(header_tree, tvb, offset, hf_nano_extensions, ett_nano_extensions, nano_extensions, ENC_LITTLE_ENDIAN, extensions);
    offset += 2;

    return offset;
}

//
// Dissect Confirm Ack
//
static int hf_nano_confirm_ack_vote_common_account = -1;
static int hf_nano_confirm_ack_vote_common_signature = -1;
static int hf_nano_confirm_ack_vote_common_sequence = -1;

static int dissect_nano_vote_common (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    proto_tree* vote_tree = proto_tree_add_subtree(tree, tvb, offset, 32 + 64 + 8, ett_nano_vote_common, NULL, "Vote Common");

    proto_tree_add_item(vote_tree, hf_nano_confirm_ack_vote_common_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(vote_tree, hf_nano_confirm_ack_vote_common_signature, tvb, offset, 64, ENC_NA);
    offset += 64;

    proto_tree_add_item(vote_tree, hf_nano_confirm_ack_vote_common_sequence, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

static int hf_nano_confirm_ack_hash = -1;

static int dissect_nano_confirm_ack (tvbuff_t* tvb, packet_info* pinfo, proto_tree* nano_tree, int offset, guint64 extensions) {
    proto_item* pi;

    int total_size = 32 + 64 + 8;
    int block_type = (extensions & 0x0f00) >> 8;
    int item_count = (extensions & 0xf000) >> 12;

    if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        total_size += item_count * 32;
    } else {
        total_size += get_block_type_size(block_type);
    }

    append_info_col(pinfo->cinfo, "Confirm Ack");

    proto_tree *tree = proto_tree_add_subtree(nano_tree, tvb, offset, total_size, ett_nano_confirm_ack, NULL, "Confirm Ack");

    offset = dissect_nano_vote_common(tvb, pinfo, tree, offset);

    if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%i Blocks)", item_count);

        proto_tree* hashes_tree = proto_tree_add_subtree(tree, tvb, offset, item_count * 32, ett_nano_confirm_ack_hashes, &pi, "Hashes List");
        for (int i = 0; i < item_count; i++) {
            proto_tree_add_item(hashes_tree, hf_nano_confirm_ack_hash, tvb, offset, 32, ENC_NA);
            offset += 32;
        }

        return offset;
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s Block)", val_to_str(block_type, VALS(nano_block_type_strings), "Unknown (%d)"));

        return dissect_nano_block(block_type, tvb, tree, offset);
    }
}

//
// Dissect Confirm Req
//

static int hf_nano_extensions_item_count = -1;
static int hf_nano_hash_pair_first = -1;
static int hf_nano_hash_pair_second = -1;

static gint ett_nano_confirm_req = -1;

static int dissect_nano_confirm_req (tvbuff_t* tvb, packet_info* pinfo, proto_tree* nano_tree, int offset, guint64 extensions) {
    proto_item *ti;
    proto_tree* hash_pair_tree;

    int block_type = (extensions & 0x0f00) >> 8;

    append_info_col(pinfo->cinfo, "Confirm Req");
    if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        col_append_str(pinfo->cinfo, COL_INFO, " (ReqByHash)");

        // Req by hash
        int item_count = (extensions & 0xf000) >> 12;

        proto_tree *tree = proto_tree_add_subtree(nano_tree, tvb, offset, item_count * 64, ett_nano_confirm_req, NULL, "Confirm Req");
        proto_tree_add_uint(tree, hf_nano_extensions_item_count, tvb, offset, 0, item_count);

        for (int i = 0; i < item_count; i++) {
            hash_pair_tree = proto_tree_add_subtree(tree, tvb, offset, 64, ett_nano_hash_pair, &ti, "Hash Pair");

            proto_tree_add_item(hash_pair_tree, hf_nano_hash_pair_first, tvb, offset, 32, ENC_BIG_ENDIAN);
            offset += 32;

            proto_tree_add_item(hash_pair_tree, hf_nano_hash_pair_second, tvb, offset, 32, ENC_BIG_ENDIAN);
            offset += 32;
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s Block)", val_to_str(block_type, VALS(nano_block_type_strings), "Unknown (%d)"));

        int block_type_size = get_block_type_size(block_type);
        proto_tree *tree = proto_tree_add_subtree(nano_tree, tvb, offset, block_type_size, ett_nano_confirm_req, NULL, "Confirm Req");
        
        return dissect_nano_block(block_type, tvb, tree, offset);
    }

    return offset;
}

//
// Dissect Telemetry Req
//
static int dissect_nano_telemetry_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nano_tree, int offset, guint64 extensions) {
    append_info_col(pinfo->cinfo, "Telemetry Req");

    return 0;
}

static int hf_nano_telemetry_ack_signature = -1;
static int hf_nano_telemetry_ack_nodeid = -1;
static int hf_nano_telemetry_ack_blockcount = -1;
static int hf_nano_telemetry_ack_cementedcount = -1;
static int hf_nano_telemetry_ack_uncheckedcount = -1;
static int hf_nano_telemetry_ack_accountcount = -1;
static int hf_nano_telemetry_ack_bandwidthcap = -1;
static int hf_nano_telemetry_ack_uptime = -1;
static int hf_nano_telemetry_ack_peercount = -1;
static int hf_nano_telemetry_ack_protocolversion = -1;
static int hf_nano_telemetry_ack_genesisblock = -1;
static int hf_nano_telemetry_ack_majorversion = -1;
static int hf_nano_telemetry_ack_minorversion = -1;
static int hf_nano_telemetry_ack_patchversion = -1;
static int hf_nano_telemetry_ack_prereleaseversion = -1;
static int hf_nano_telemetry_ack_maker = -1;
static int hf_nano_telemetry_ack_timestamp = -1;
static int hf_nano_telemetry_ack_activedifficulty = -1;

static gint ett_nano_telemetry_ack = -1;

static int dissect_nano_telemetry_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nano_tree, int offset, guint64 extensions) {
    append_info_col(pinfo->cinfo, "Telemetry Ack");

    guint32 payload_size = extensions & 0x3ff;
    proto_tree *telemetry_tree = proto_tree_add_subtree(nano_tree, tvb, offset, payload_size, ett_nano_telemetry_ack, NULL, "Telemetry Ack");

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_signature, tvb, offset, 64, ENC_BIG_ENDIAN);
    offset += 64;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_nodeid, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_blockcount, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_cementedcount, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_uncheckedcount, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_accountcount, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_bandwidthcap, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_uptime, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_peercount, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_protocolversion, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_genesisblock, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_majorversion, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_minorversion, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_patchversion, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_prereleaseversion, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_maker, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_timestamp, tvb, offset, 8, ENC_TIME_MSECS);
    offset += 8;

    proto_tree_add_item(telemetry_tree, hf_nano_telemetry_ack_activedifficulty, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

//
// Dissect Node ID Handshake
//

static int hf_nano_node_id_handshake_is_query = -1;
static int hf_nano_node_id_handshake_is_response = -1;

static int hf_nano_node_id_handshake_query_cookie = -1;

static int hf_nano_node_id_handshake_response_account = -1;
static int hf_nano_node_id_handshake_response_signature = -1;

static gint ett_nano_node_id_handshake = -1;
static gint ett_nano_node_id_handshake_request = -1;

static int dissect_nano_node_id_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nano_tree, int offset, guint64 extensions) {
    guint total_body_size = 0;
    guint32 is_query = extensions & 0x0001;
    guint32 is_response = extensions & 0x0002;

    append_info_col(pinfo->cinfo, "Node ID Handshake");

    // Is query
    if (is_query) {
        col_append_str(pinfo->cinfo, COL_INFO, " (Query) ");
        total_body_size += 32;
    }

    // Is response
    if (is_response) {
        col_append_str(pinfo->cinfo, COL_INFO, " (Response) ");
        total_body_size += 32 + 64;
    }

    
    proto_tree *handshake_tree = proto_tree_add_subtree(nano_tree, tvb, offset, total_body_size, ett_nano_node_id_handshake, NULL, "Node ID Handshake");
    proto_tree_add_boolean(handshake_tree, hf_nano_node_id_handshake_is_query, tvb, offset, 0, is_query);
    proto_tree_add_boolean(handshake_tree, hf_nano_node_id_handshake_is_response, tvb, offset, 0, is_response);

    if (is_query) {
        proto_tree_add_item(handshake_tree, hf_nano_node_id_handshake_query_cookie, tvb, offset, 32, ENC_NA);
        offset += 32;
    }

    if (is_response) {
        proto_tree_add_item(handshake_tree, hf_nano_node_id_handshake_response_account, tvb, offset, 32, ENC_NA);
        offset += 32;

        proto_tree_add_item(handshake_tree, hf_nano_node_id_handshake_response_signature, tvb, offset, 64, ENC_NA);
        offset += 64;
    }

    return offset;
}


//
// Dissect Publish
//
static int dissect_nano_publish (tvbuff_t* tvb, packet_info* pinfo, proto_tree* nano_tree, int offset, guint64 extensions) {
    int block_type = (extensions & 0x0f00) >> 8;

    append_info_col(pinfo->cinfo, "Publish");
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(block_type, VALS(nano_block_type_strings), "Unknown (%d)"));

    int block_type_size = get_block_type_size(block_type);
    proto_tree *tree = proto_tree_add_subtree(nano_tree, tvb, offset, block_type_size, ett_nano_confirm_req, NULL, "Publish");

    return dissect_nano_block(block_type, tvb, tree, offset);
}

//
// Dissect Bulk Pull
//
static int hf_nano_bulk_pull_start = -1;
static int hf_nano_bulk_pull_end = -1;
static int hf_nano_bulk_pull_extended_zero = -1;
static int hf_nano_bulk_pull_extended_count = -1;
static int hf_nano_bulk_pull_extended_reserved = -1;

static int dissect_nano_bulk_pull_request (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int extensions) {
    append_info_col(pinfo->cinfo, "Bulk Pull Request");

    int total_body_size = 32 + 32;
    int is_extended_param_present = extensions & 0x0001;

    if (is_extended_param_present) {
        total_body_size += 1 + 4 + 3;
    }

    proto_tree *bulk_pull_tree = proto_tree_add_subtree(tree, tvb, offset, total_body_size, ett_nano_bulk_pull, NULL, "Bulk Pull Request");

    proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_start, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_end, tvb, offset, 32, ENC_NA);
    offset += 32;

    // Check if extended param is present
    if (is_extended_param_present) {
        proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_extended_zero, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_extended_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_extended_reserved, tvb, offset, 3, ENC_NA);
        offset += 3;
    }

    return offset;
}
//
// Dissect Bulk Pull Account
//
static int hf_nano_bulk_pull_account_public_key = -1;
static int hf_nano_bulk_pull_account_minimum_amount = -1;
static int hf_nano_bulk_pull_account_flags = -1;

static int dissect_nano_bulk_pull_account (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    proto_tree *bulk_pull_tree = proto_tree_add_subtree(tree, tvb, offset, 32 + 16 + 1, ett_nano_bulk_pull_account, NULL, "Bulk Pull Account");

    proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_account_public_key, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_account_minimum_amount, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(bulk_pull_tree, hf_nano_bulk_pull_account_flags, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}
//
// Dissect Nano Message
//
static int hf_nano_frontier_req_start_account = -1;
static int hf_nano_frontier_req_age = -1;
static int hf_nano_frontier_req_count = -1;

static int dissect_nano_frontier_req (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    append_info_col(pinfo->cinfo, "Frontier Req");

    proto_tree *frontier_req_tree = proto_tree_add_subtree(tree, tvb, offset, 32 + 4 + 4, ett_nano_frontier_req, NULL, "Frontier Req");

    proto_tree_add_item(frontier_req_tree, hf_nano_frontier_req_start_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(frontier_req_tree, hf_nano_frontier_req_age, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(frontier_req_tree, hf_nano_frontier_req_count, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}
//
// Dissect headerless packets
//
static int hf_nano_frontier_response_account = -1;
static int hf_nano_frontier_response_frontier_hash = -1;

static int dissect_nano_headerless_frontier_response (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, struct nano_session_state* session_state) {
    append_info_col(pinfo->cinfo, "Frontier Response");

    int offset = 0;
    proto_tree *frontier_response_tree = proto_tree_add_subtree(tree, tvb, 0, 32 + 32, ett_nano_frontier_response, NULL, "Frontier Response");

    guint32 account = tvb_get_guint32(tvb, 0, ENC_NA);
    proto_tree_add_item(frontier_response_tree, hf_nano_frontier_response_account, tvb, offset, 32, ENC_NA);
    offset += 32;

    guint32 frontier_hash = tvb_get_guint32(tvb, 0, ENC_NA);

    proto_tree_add_item(frontier_response_tree, hf_nano_frontier_response_frontier_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    if (account == 0 && frontier_hash == 0) {
        session_state->client_packet_type = NANO_PACKET_TYPE_INVALID;
    }

    return offset;
}

static int hf_nano_bulk_pull_response_block_type = -1;

static int dissect_nano_headerless_bulk_pull_response (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, struct nano_session_state* session_state) {
    append_info_col(pinfo->cinfo, "Bulk Pull Response");

    int block_type = tvb_get_guint8(tvb, 0);

    int total_size = 1;
    if (block_type != NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        total_size += get_block_type_size(block_type);
    }

    int offset = 0;
    proto_tree *bulk_pull_response_tree = proto_tree_add_subtree(tree, tvb, 0, total_size, ett_nano_bulk_pull_response, NULL, "Bulk Pull Response");

    proto_tree_add_item(bulk_pull_response_tree, hf_nano_bulk_pull_response_block_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [BULK PULL RESPONSE END]");
        session_state->client_packet_type = NANO_PACKET_TYPE_NOT_A_TYPE;
    } else {
        offset += dissect_nano_block(block_type, tvb, bulk_pull_response_tree, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s Block)", val_to_str(block_type, VALS(nano_block_type_strings), "Unknown (%d)"));
    }

    return offset;
}

static int dissect_nano_headerless_bulk_push_body (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, struct nano_session_state* session_state) {
    append_info_col(pinfo->cinfo, "Bulk Push Data");

    int block_type = tvb_get_guint8(tvb, 0);

    int total_size = 1;
    if (block_type != NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        total_size += get_block_type_size(block_type);
    }

    int offset = 0;
    proto_tree *bulk_push_response_tree = proto_tree_add_subtree(tree, tvb, 0, total_size, ett_nano_bulk_pull_response, NULL, "Bulk Push Data");

    proto_tree_add_item(bulk_push_response_tree, hf_nano_bulk_pull_response_block_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [BULK PUSH END]");
        session_state->client_packet_type = NANO_PACKET_TYPE_NOT_A_TYPE;
    } else {
        offset += dissect_nano_block(block_type, tvb, bulk_push_response_tree, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s Block)", val_to_str(block_type, VALS(nano_block_type_strings), "Unknown (%d)"));
    }

    return offset;
}

static int dissect_headerless_packet_client (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, struct nano_session_state* session_state) {
    switch (session_state->client_packet_type) {
        case NANO_PACKET_TYPE_BULK_PUSH:
            return dissect_nano_headerless_bulk_push_body(tvb, pinfo, tree, session_state);
    }

    append_info_col(pinfo->cinfo, "UNKNOWN HEADERLESS [CLIENT] Packet");
    return 0;
}

static int dissect_headerless_packet_server (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, struct nano_session_state* session_state) {
    switch (session_state->client_packet_type) {
        case NANO_PACKET_TYPE_FRONTIER_REQ:
            return dissect_nano_headerless_frontier_response(tvb, pinfo, tree, session_state);
        case NANO_PACKET_TYPE_BULK_PULL:
            return dissect_nano_headerless_bulk_pull_response(tvb, pinfo, tree, session_state);
    }

    append_info_col(pinfo->cinfo, "UNKNOWN HEADERLESS [SERVER] Packet");
    return 0;
}


static int dissect_headerless_packet (tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, struct nano_session_state* session_state) {
    // is client
    if (pinfo->destport == session_state->server_port) {
        return dissect_headerless_packet_client(tvb, pinfo, tree, session_state);
    } else {
        return dissect_headerless_packet_server(tvb, pinfo, tree, session_state);
    }
}

//
// Dissect Nano Message
//
static int does_prev_packet_expect_headerless_response (struct nano_session_state* session_state) {
    switch (session_state->client_packet_type) 	{
        case NANO_PACKET_TYPE_BULK_PULL:
        case NANO_PACKET_TYPE_BULK_PUSH:
        case NANO_PACKET_TYPE_FRONTIER_REQ:
            return 1;
    }

    return 0;
}

static int dissect_nano (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    struct nano_session_state *session_state = (struct nano_session_state *) data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Nano");

    proto_item *ti = proto_tree_add_item(tree, proto_nano, tvb, 0, -1, ENC_NA);
    proto_tree *nano_tree = proto_item_add_subtree(ti, ett_nano);

    if (does_prev_packet_expect_headerless_response (session_state)) {
        return dissect_headerless_packet(tvb, pinfo, nano_tree, session_state);
    }

    // Check that the packet is long enough for it to belong to us.
    if (tvb_reported_length (tvb) < NANO_HEADER_LENGTH) {
        append_info_col(pinfo->cinfo, "[DEBUG] ENCOUNTERED SMALL HEADER SIZE IN PACKET");
        return 0;
    }

    char first_byte = tvb_get_gint8(tvb, 0);
    if (first_byte != 'R') {
        append_info_col(pinfo->cinfo, "ENCOUNTERED INVALID MAGIC NUMBER IN PACKET!");
        return 0;
    }

    guint nano_packet_type;
    guint64 extensions;
    int offset = dissect_nano_header(tvb, nano_tree, 0, &nano_packet_type, &extensions);

    session_state->client_packet_type = nano_packet_type;
    // call specific dissectors for specific packet types
    switch (nano_packet_type) {
        case NANO_PACKET_TYPE_TELEMETRY_ACK:
            return dissect_nano_telemetry_ack(tvb, pinfo, nano_tree, offset, extensions);
        case NANO_PACKET_TYPE_TELEMETRY_REQ:
            return dissect_nano_telemetry_req(tvb, pinfo, nano_tree, offset, extensions);
        case NANO_PACKET_TYPE_NODE_ID_HANDSHAKE:
            return dissect_nano_node_id_handshake(tvb, pinfo, nano_tree, offset, extensions);
        case NANO_PACKET_TYPE_KEEPALIVE:
            return dissect_nano_keepalive(tvb, pinfo, nano_tree, offset);
        case NANO_PACKET_TYPE_CONFIRM_REQ:
            return dissect_nano_confirm_req(tvb, pinfo, nano_tree, offset, extensions);
        case NANO_PACKET_TYPE_CONFIRM_ACK:
            return dissect_nano_confirm_ack(tvb, pinfo, nano_tree, offset, extensions);
        case NANO_PACKET_TYPE_PUBLISH:
            return dissect_nano_publish(tvb, pinfo, nano_tree, offset, extensions);
        case NANO_PACKET_TYPE_BULK_PULL_ACCOUNT:
            return dissect_nano_bulk_pull_account(tvb, pinfo, nano_tree, offset);
        case NANO_PACKET_TYPE_FRONTIER_REQ:
            return dissect_nano_frontier_req(tvb, pinfo, nano_tree, offset);
        case NANO_PACKET_TYPE_BULK_PULL:
            return dissect_nano_bulk_pull_request(tvb, pinfo, nano_tree, offset, extensions);
        default:
            append_info_col(pinfo->cinfo, val_to_str(nano_packet_type, VALS(nano_packet_type_strings), "Unknown (%d)"));
    }

    return tvb_captured_length(tvb);
}

static guint get_nano_message_len (packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    struct nano_session_state *session_state = (struct nano_session_state*) data;

    // check if we're expecting a headerless packet
    if (session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PULL) {
        int nano_block_type = tvb_get_guint8(tvb, offset);

        if (nano_block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
            return 1;
        }

        // 1 byte for block type and rest is the block itself
        return 1 + get_block_type_size(nano_block_type); 
    }

    if (session_state->client_packet_type == NANO_PACKET_TYPE_FRONTIER_REQ) {
        return 32 + 32;
    }

    if (session_state->client_packet_type == NANO_PACKET_TYPE_BULK_PUSH) {
        // we're in the middle of a bulk push, so we expect a block type (uint8) and a block
        int nano_block_type = tvb_get_guint8(tvb, offset);

        switch (nano_block_type) {
            case NANO_BLOCK_TYPE_NOT_A_BLOCK:
                return 1;
            case NANO_BLOCK_TYPE_SEND:
                return 1 + NANO_BLOCK_SIZE_SEND;
            case NANO_BLOCK_TYPE_RECEIVE:
                return 1 + NANO_BLOCK_SIZE_RECEIVE;
            case NANO_BLOCK_TYPE_OPEN:
                return 1 + NANO_BLOCK_SIZE_OPEN;
            case NANO_BLOCK_TYPE_CHANGE:
                return 1 + NANO_BLOCK_SIZE_CHANGE;
            case NANO_BLOCK_TYPE_STATE:
                return 1 + NANO_BLOCK_SIZE_STATE;
            default:
                // this is invalid
                return tvb_captured_length(tvb) - offset;
        }
    }

    // we expect a client command, this starts with a full Nano header
    if (tvb_captured_length(tvb) - offset < NANO_HEADER_LENGTH) {
        return 0;
    }

    int nano_packet_type = tvb_get_guint8(tvb, offset + 5);
    guint16 extensions = tvb_get_guint16(tvb, offset + 6, ENC_LITTLE_ENDIAN);

    switch (nano_packet_type) {
        case NANO_PACKET_TYPE_TELEMETRY_ACK:
            return NANO_HEADER_LENGTH + 64 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 1 + 32 + 1 + 1 + 1 + 1 + 1 + 8 + 8;
        case NANO_PACKET_TYPE_TELEMETRY_REQ:
            return NANO_HEADER_LENGTH + 0;
        case NANO_PACKET_TYPE_NODE_ID_HANDSHAKE:
            {
                guint32 is_query = extensions & 0x0001;
                guint32 is_response = extensions & 0x0002;
                guint message_len = 0;

                if (is_query) message_len += 32;
                if (is_response) message_len += 32 + 64;

                return NANO_HEADER_LENGTH + message_len;
            }
        case NANO_PACKET_TYPE_KEEPALIVE:
            return NANO_HEADER_LENGTH + (16 + 2) * 8;
        case NANO_PACKET_TYPE_CONFIRM_REQ:
            {
                int block_type = (extensions & 0x0f00) >> 8;
                if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
                    // req by hash
                    int item_count = (extensions & 0xf000) >> 12;
                    return NANO_HEADER_LENGTH + item_count * 64;
                } else {
                    switch (block_type) {
                        case NANO_BLOCK_TYPE_SEND:
                            return NANO_HEADER_LENGTH + NANO_BLOCK_SIZE_SEND;
                        case NANO_BLOCK_TYPE_RECEIVE:
                            return NANO_HEADER_LENGTH + NANO_BLOCK_SIZE_RECEIVE;
                        case NANO_BLOCK_TYPE_OPEN:
                            return NANO_HEADER_LENGTH + NANO_BLOCK_SIZE_OPEN;
                        case NANO_BLOCK_TYPE_CHANGE:
                            return NANO_HEADER_LENGTH + NANO_BLOCK_SIZE_CHANGE;
                        case NANO_BLOCK_TYPE_STATE:
                            return NANO_HEADER_LENGTH + NANO_BLOCK_SIZE_STATE;
                    }
                }
            }
        case NANO_PACKET_TYPE_CONFIRM_ACK:
            {
                int total_size = 32 + 64 + 8;
                int block_type = (extensions & 0x0f00) >> 8;
                int item_count = (extensions & 0xf000) >> 12;

                if (block_type == NANO_BLOCK_TYPE_NOT_A_BLOCK) {
                    total_size += item_count * 32;
                } else {
                    total_size += get_block_type_size(block_type);
                }

                return NANO_HEADER_LENGTH + total_size;
            }
    }

    return tvb_captured_length(tvb) - offset;
}

// dissect a Nano bootstrap packet (TCP)
static int dissect_nano_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    col_clear(pinfo->cinfo, COL_INFO);

    // Setup conversation stuff
    struct nano_session_state *session_state, *packet_session_state;
    conversation_t *conversation = find_or_create_conversation(pinfo);

    // try to find session state
    session_state = (struct nano_session_state *) conversation_get_proto_data(conversation, proto_nano);
    if (!session_state) {
        // create new session state
        session_state = wmem_new0(wmem_file_scope(), struct nano_session_state);
        session_state->client_packet_type = NANO_PACKET_TYPE_INVALID;
        session_state->server_port = pinfo->match_uint;
        conversation_add_proto_data(conversation, proto_nano, session_state);
    }

    // check if we have a session state associated with the packet (start state for this packet)
    packet_session_state = (struct nano_session_state *)p_get_proto_data(wmem_file_scope(), pinfo, proto_nano, 0);
    if (!packet_session_state) {
        // this packet does not have a stored session state, get it from the conversation
        packet_session_state = wmem_new0(wmem_file_scope(), struct nano_session_state);
        memcpy(packet_session_state, session_state, sizeof(struct nano_session_state));
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nano, 0, packet_session_state);
    } else {
        // this packet has a stored session state, take this as a starting point
        memcpy(session_state, packet_session_state, sizeof(struct nano_session_state));
    }

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 1, get_nano_message_len, dissect_nano, session_state);

    return tvb_captured_length(tvb);
}

void proto_register_nano(void)
{
    static hf_register_info hf[] = {
        {
            &hf_nano_magic_number,
            { "Magic Number", "nano.magic_number",
            FT_STRING, STR_ASCII, NULL, 0x00,
            "Nano Protocol Magic Number", HFILL }
        },
        {
            &hf_nano_version_max,
            { "Maximum Version", "nano.version_max",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Maximum Supported Protocol Version", HFILL }
        },
        {
            &hf_nano_version_using,
            { "Using Version", "nano.version_using",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Used Protocol Version", HFILL }
        },
        {
            &hf_nano_version_min,
            { "Minimum Version", "nano.version_min",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            "Minimum Supported Protocol Version", HFILL }
        },
        {
            &hf_nano_packet_type,
            { "Packet Type", "nano.packet_type",
            FT_UINT8, BASE_DEC_HEX, VALS(nano_packet_type_strings), 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_extensions,
            { "Extensions Field", "nano.extensions",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_extensions_item_count,
            { "Item Count", "nano.extensions.item_count",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_node_id_handshake_is_query,
            { "Is Request", "nano.node_id_handshake.is_query",
            FT_BOOLEAN, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_node_id_handshake_is_response,
            { "Is Response", "nano.node_id_handshake.is_response",
            FT_BOOLEAN, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_node_id_handshake_query_cookie,
            { "Cookie", "nano.node_id_handshake.cookie",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_node_id_handshake_response_account,
            { "Response Account", "nano.node_id_handshake.response_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_node_id_handshake_response_signature,
            { "Response Signature", "nano.node_id_handshake.response_signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_extensions_block_type,
            { "Block Type", "nano.extensions.block_type",
            FT_UINT16, BASE_HEX, VALS(nano_block_type_strings), 0x0f00,
            NULL, HFILL }
        },
        {
            &hf_nano_keepalive_peer_ip,
            { "Peer IP Address", "nano.keepalive.peer_ip",
            FT_IPv6, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_keepalive_peer_port,
            { "Peer Port", "nano.keepalive.peer_port",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_hash_previous,
            { "Previous Block Hash", "nano.block.hash_previous",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_hash_source,
            { "Source Block Hash", "nano.block.hash_source",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_signature,
            { "Signature", "nano.block.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_work,
            { "Work", "nano.block.work",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_destination_account,
            { "Destination Account", "nano.block.destination_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_balance,
            { "Balance", "nano.block.balance",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_account,
            { "Account", "nano.block.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_representative_account,
            { "Representative Account", "nano.block.representative_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_block_link,
            { "Link", "nano.block.link",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_vote_account,
            { "Account", "nano.vote.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_vote_signature,
            { "Signature", "nano.vote.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_vote_sequence,
            { "Sequence", "nano.vote.sequence",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_account,
            { "Account", "nano.bulk_pull.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_block_hash_end,
            { "End Block Hash", "nano.bulk_pull_block.hash_end",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_blocks_min_hash,
            { "Min Block Hash", "nano.bulk_pull_blocks.min_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_blocks_max_hash,
            { "Max Block Hash", "nano.bulk_pull_blocks.max_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_blocks_mode,
            { "Mode", "nano.bulk_pull_blocks.mode",
            FT_UINT8, BASE_DEC_HEX, VALS(nano_bulk_pull_blocks_mode_strings), 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_blocks_max_count,
            { "Max Count", "nano.bulk_pull_blocks.max_count",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_push_block_type,
            { "Block Type", "nano.bulk_push.block_type",
            FT_UINT8, BASE_HEX, VALS(nano_block_type_strings), 0x00,
            NULL, HFILL }
        },
        /* Telemetry Ack */
        {
            &hf_nano_telemetry_ack_signature,
            { "Signature", "nano.telemetry_ack.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_nodeid,
            { "Node ID", "nano.telemetry_ack.nodeid",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_blockcount,
            { "Block Count", "nano.telemetry_ack.blockcount",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_cementedcount,
            { "Cemented Count", "nano.telemetry_ack.cementedcount",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_uncheckedcount,
            { "Unchecked Count", "nano.telemetry_ack.uncheckedcount",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_accountcount,
            { "Account Count", "nano.telemetry_ack.accountcount",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_bandwidthcap,
            { "Bandwidth Cap", "nano.telemetry_ack.bandwidthcap",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_uptime,
            { "Uptime", "nano.telemetry_ack.uptime",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_peercount,
            { "Peer Count", "nano.telemetry_ack.peercount",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_protocolversion,
            { "Protocol Version", "nano.telemetry_ack.protocolversion",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_genesisblock,
            { "Genesis Block", "nano.telemetry_ack.genesisblock",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_majorversion,
            { "Major Version", "nano.telemetry_ack.majorversion",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_minorversion,
            { "Minor Version", "nano.telemetry_ack.minorversion",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_patchversion,
            { "Patch Version", "nano.telemetry_ack.patchversion",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_prereleaseversion,
            { "Pre-Release Version", "nano.telemetry_ack.prereleaseversion",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_maker,
            { "Maker", "nano.telemetry_ack.maker",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_timestamp,
            { "Timestamp", "nano.telemetry_ack.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_telemetry_ack_activedifficulty,
            { "Active Difficulty", "nano.telemetry_ack.activedifficulty",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        /* Confirm Req */
        {
            &hf_nano_hash_pair_first,
            { "First", "nano.confirm_req.hash_pair.first",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_hash_pair_second,
            { "Second", "nano.confirm_req.hash_pair.second",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Bulk Pull Account */
        {
            &hf_nano_bulk_pull_account_public_key,
            { "Account Public Key", "nano.bulk_pull_account.account_public_key",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_account_minimum_amount,
            { "Minimum Amount", "nano.bulk_pull_account.minimum_amount",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_account_flags,
            { "Flags", "nano.bulk_pull_account.flags",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Frontier Req */
        {
            &hf_nano_frontier_req_start_account,
            { "Account", "nano.frontier_req.start_account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_frontier_req_age,
            { "Age", "nano.frontier_req.age",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_frontier_req_count,
            { "Count", "nano.frontier_req.count",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* Frontier Response */
        {
            &hf_nano_frontier_response_account,
            { "Account", "nano.frontier_response.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_frontier_response_frontier_hash,
            { "Frontier Hash", "nano.frontier_response.frontier_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Bulk Pull Request */
        {
            &hf_nano_bulk_pull_start,
            { "Start Account", "nano.bulk_pull.start",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_end,
            { "End Account", "nano.bulk_pull.end",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_extended_zero,
            { "Account", "nano.bulk_pull.extended.zero",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_extended_count,
            { "Count", "nano.bulk_pull.extended.count",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_bulk_pull_extended_reserved,
            { "Reserved", "nano.bulk_pull.extended.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Bulk Pull Response */
        {
            &hf_nano_bulk_pull_response_block_type,
            { "Block Type", "nano.bulk_pull.block_type",
            FT_UINT8, BASE_DEC_HEX, VALS(nano_block_type_strings), 0x00,
            NULL, HFILL }
        },
        /* Confirm Ack */
        /* + Vote Common */
        {
            &hf_nano_confirm_ack_vote_common_account,
            { "Account", "nano.confirm_ack.vote_common.account",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_confirm_ack_vote_common_signature,
            { "Signature", "nano.confirm_ack.vote_common.signature",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        {
            &hf_nano_confirm_ack_vote_common_sequence,
            { "Sequence", "nano.confirm_ack.vote_common.sequence",
            FT_UINT64, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        /* + Vote By Hash */
        {
            &hf_nano_confirm_ack_hash,
            { "Hash", "nano.confirm_ack.vote_by_hash.hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_nano,

        &ett_nano_header,
        &ett_nano_extensions,

        &ett_nano_node_id_handshake,
        &ett_nano_node_id_handshake_request,

        &ett_nano_telemetry_ack,

        &ett_nano_confirm_req,

        &ett_nano_peers,
        &ett_nano_peer_details,

        &ett_nano_hash_pair,

        &ett_nano_block,
        &ett_nano_vote,
        &ett_nano_bulk_pull,
        &ett_nano_bulk_pull_response,
        &ett_nano_bulk_pull_account,

        &ett_nano_frontier_req,
        &ett_nano_frontier_response,

        &ett_nano_bulk_pull_blocks,

        &ett_nano_vote_common,

        &ett_nano_confirm_ack,
        &ett_nano_confirm_ack_hashes
    };

    proto_nano = proto_register_protocol("Nano Cryptocurrency Protocol", "Nano", "nano");

    proto_register_field_array(proto_nano, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_nano(void)
{
    nano_tcp_handle = register_dissector("nano-over-tcp", dissect_nano_tcp, proto_nano);
    dissector_add_uint_with_preference("tcp.port", NANO_TCP_PORT, nano_tcp_handle);
}

/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
