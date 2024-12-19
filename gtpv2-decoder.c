#include "gtpv2-decoder.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

#define GTPV2_IMSI 0x01

static inline int decoderGtpV2Tlv(unsigned char *data, int dataLen,
                                  unsigned char type, unsigned char **out_data,
                                  int *out_dataLen)
{
    int offset = 0;
    *out_dataLen = 0;
    if (data[0] == type) {
        int length = ntohs(*(short *)&data[1]);
        offset = length + 4;
        if (dataLen < offset) {
            return 0;
        }
        *out_data = data + 4;
        *out_dataLen = length;
    }

    return offset;
}

static int decodeImsi(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;

    int ret =
        decoderGtpV2Tlv(data, datalen, GTPV2_IMSI, &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }
    BCD2ASCII(p_value, p_value_len * 2, gtp->b2.imsi, MAX_IMSI_BCD_LEN + 1);
    return ret;
}

int registerGtpv2IEParsers(onIEParse ietable[MAX_IE])
{
    ietable[GTPV2_IMSI] = decodeImsi;
    return 1;
}
