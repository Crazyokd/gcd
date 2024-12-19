#include "gtpc-decoder.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "gtpv0-decoder.h"
#include "gtpv1-decoder.h"
#include "gtpv2-decoder.h"

static int gtpv1FallbackTlv(uint8_t *data, uint32_t len, gtp_t *ud)
{
    (void)ud;
    uint32_t offset = 3 + ntohs(*(uint16_t *)&data[1]);
    if (len < offset) {
        return -1;
    }
    return offset;
}

static int gtpv2FallbackTlv(uint8_t *data, uint32_t len, gtp_t *ud)
{
    uint32_t offset = 4 + ntohs(*(uint16_t *)&data[1]);
    if (len < offset) {
        return -1;
    }
    return offset;
}

static int decodeGtpcHeader(uint8_t *data, uint32_t len, gtp_t *gtp)
{
    uint32_t oft = 0;
    gtp_header_t *hdr = &gtp->hdr;

    hdr->version = (*data >> 5) & 0x07;
    switch (hdr->version) {
    case 0: {
        uint8_t pt = (*data >> 4) & 0x01; // protocol type
        if (pt != 1) {
            return -1; // not GTP
        }
        uint8_t sndcp = *data & 0x01; // Is SNDCP N-PDU included?
        ++oft;
        hdr->msgType = data[oft++];
        hdr->msgLen = ntohs(*(uint16_t *)(data + oft));
        oft += 2;
        hdr->sqn = ntohs(*(uint16_t *)(data + oft));
        oft += 2;
        // uint16_t flowLabel = ntohs(*(uint16_t *)(data + oft));
        oft += 2;
        if (sndcp == 1) {
            // get SNDCP N-PDU LLC Number
        }
        oft += 4;
        char tid[9];
        memcpy(tid, data + oft, 8);
        oft += 8;
        break;
    }
    case 1: {
        uint8_t pt = (*data >> 4) & 0x01; // protocol type
        if (pt != 1) {
            return -1; // not GTP
        }
        uint8_t ext = (*data >> 2) & 0x01; // Is Next Extension Header present
        uint8_t sqn = (*data >> 1) & 0x01; // Is Sequence Number present?
        // uint8_t pdu = *data & 0x01; // Is N-PDU number present?
        ++oft;
        hdr->msgType = data[oft++];
        hdr->msgLen = ntohs(*(uint16_t *)(data + oft));
        oft += 2;
        hdr->teid = ntohl(*(uint32_t *)(data + oft));
        oft += 4;
        if (sqn == 1) {
            hdr->sqn = ntohs(*(uint16_t *)(data + oft));
            oft += 2;
        }
        if (ext) {}
        oft += 2;
        while (data[oft - 1] == 0x02) {
            // next extension header type
            oft += 4;
        }
        break;
    }
    case 2: {
        uint8_t teidFlag = (*data >> 3) & 0x01;
        ++oft;
        hdr->msgType = data[oft++];
        hdr->msgLen = ntohs(*(uint16_t *)(data + oft));
        oft += 2;
        if (len != hdr->msgLen + oft) {
            return -1;
        }
        if (teidFlag) {
            hdr->teid = ntohl(*(uint32_t *)(data + oft));
            oft += 4;
        }
        hdr->teid = (ntohl(*(uint32_t *)(data + oft)) >> 8) & 0x00ffffff;
        oft += 4;
        break;
    }
    default:
        printf("unsupported gtpc version[%u]\n", hdr->version);
        return -1;
    }
    return oft;
}

#define MAX_GTPC_VERSION 2
static onIEParse ie_table[MAX_GTPC_VERSION + 1][MAX_IE + 1];

static int decodeGtpcBody(uint8_t *data, uint32_t len, gtp_t *gtp,
                          onIEParse ietable[MAX_IE])
{
    uint32_t idx = 0;
    int ret = 0;
    while (idx < len) {
        onIEParse parse = ietable[data[idx]];
        if (!parse) {
            // warning
            printf("unknown ie[%u] or corresponding parser not be registered\n",
                   data[idx]);
            // try to use unknown tlvDecoder
            if (gtp->hdr.version < 2 && data[idx] & 0x80) {
                parse = gtpv1FallbackTlv;
            } else if (gtp->hdr.version == 2) {
                parse = gtpv2FallbackTlv;
            } else {
                break;
            }
        }
        ret = parse(data + idx, len - idx, gtp);
        if (ret < 0) {
            printf("parse ie error in offset[%u]\n", idx);
            break;
        }
        idx += ret;
    }
    return idx == len;
}

int registerIEParsers()
{
    memset(ie_table, 0, sizeof(ie_table));
    return registerGtpv0IEParsers(ie_table[0])
        && registerGtpv1IEParsers(ie_table[1])
        && registerGtpv2IEParsers(ie_table[2]);
}

int decodeGtpc(uint8_t *data, uint32_t len, gtp_t *gtp)
{
    // decode header
    int hdr_offset = decodeGtpcHeader(data, len, gtp);
    if (hdr_offset == -1) {
        printf("decode gtpc header error\n");
        return -1;
    }

    return decodeGtpcBody(data + hdr_offset, len - hdr_offset, gtp,
                          ie_table[gtp->hdr.version]);
}
