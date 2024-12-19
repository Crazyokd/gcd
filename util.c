#include "util.h"

#include <arpa/inet.h>
#include <stdio.h>

#include "macros.h"

uint8_t BCD2ASCII(uint8_t *bcd, uint8_t bcdLen, char *ascii, uint8_t asciiLen)
{
    int i = 0, j = 0;
    if (asciiLen < bcdLen) return 0;
    if ((bcdLen == 0) || (asciiLen == 0)) return 0;

    ascii[0] = 0;

    for (i = 0; i < bcdLen; i++) {
        j = i / 2;
        ascii[i] = (bcd[j] & 0x0F) + 0x30;
        switch (ascii[i]) {
        case 0x3D: {
            ascii[i] = '*';
        } break;
        case 0x3E: {
            ascii[i] = '#';
        } break;
        default:
            break;
        }
        ++i;
        ascii[i] = ((bcd[j] & 0xF0) >> 4) + 0x30;
        switch (ascii[i]) {
        case 0x3D: {
            ascii[i] = '*';
        } break;
        case 0x3E: {
            ascii[i] = '#';
        } break;
        default:
            break;
        }
    }

    int has_st = 0;
    if (bcdLen % 2 == 0) {
        if ((bcd[bcdLen / 2 - 1] & 0xF0) == 0xF0) has_st = 1;
    } else {
        if ((bcd[bcdLen / 2] & 0x0F) == 0x0F) has_st = 1;
    }
    if (has_st == 1)
        ascii[bcdLen - 1] = 0;
    else {
        if (bcdLen == asciiLen) {
            ascii[0] = 0;
            return 0;
        }
        ascii[bcdLen] = 0;
    }

    return bcdLen;
}

int decodeMccMncLac(uint8_t *data, char *mcc, char *mnc, uint16_t *lac)
{
    int offset = 0;
    BCD2ASCII(data + offset, MAX_MCC_SIZE + 1, mcc, MAX_MCC_SIZE + 1);
    offset += 1;
    uint8_t flag = (data[offset] >> 4) & 0x0F;
    offset += 1;
    if (flag == 0x0F) {
        snprintf(mnc, MAX_MCC_SIZE+1, "%x%x", data[offset] & 0x0F,
                 (data[offset] >> 4) & 0x0F);
    } else {
        snprintf(mnc, MAX_MNC_SIZE+1, "%x%x%x", data[offset] & 0x0F,
                 (data[offset] >> 4) & 0x0F, flag);
    }
    offset += 1;
    *lac = ntohs(*(uint16_t *)(data + offset));
    offset += 2;

    return offset;
}
