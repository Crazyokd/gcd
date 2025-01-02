#include "gtpv0-decoder.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

/* below macros are based on `3GPP TS 09.60 V7.10.0` */
#define GTPV0_RESERVED                       0x0
#define GTPV0_CAUSE                          0x01
#define GTPV0_CAUSE_LEN                      1
#define GTPV0_IMSI                           0x02
#define GTPV0_IMSI_LEN                       8
#define GTPV0_ROUTING_AREA_IDENTITY          0x03
#define GTPV0_ROUTING_AREA_IDENTITY_LEN      6
#define GTPV0_TLLI                           0x04
#define GTPV0_TLLI_LEN                       4
#define GTPV0_P_TMSI                         0x05
#define GTPV0_P_TMSI_LEN                     4
#define GTPV0_QUALITY_OF_SERVICE             0x06
#define GTPV0_QUALITY_OF_SERVICE_LEN         3

#define GTPV0_REORDERING_REQUIRED            0x08
#define GTPV0_REORDERING_REQUIRED_LEN        1
#define GTPV0_AUTHENTICATION_TRIPLET         0x09
#define GTPV0_AUTHENTICATION_TRIPLET_LEN     28

#define GTPV0_MAP_CAUSE                      0x0B
#define GTPV0_MAP_CAUSE_LEN                  1
#define GTPV0_P_TMSI_SIGNATURE               0x0C
#define GTPV0_P_TMSI_SIGNATURE_LEN           3
#define GTPV0_MS_VALIDATED                   0x0D
#define GTPV0_MS_VALIDATED_LEN               1
#define GTPV0_RECOVERY                       0x0e
#define GTPV0_RECOVERY_LEN                   1
#define GTPV0_SELECTION_MODE                 0x0F
#define GTPV0_SELECTION_MODE_LEN             1
#define GTPV0_FLOW_LABEL_DATA_I              0x10
#define GTPV0_FLOW_LABEL_DATA_I_LEN          2
#define GTPV0_FLOW_LABEL_SIGNALLING          0x11
#define GTPV0_FLOW_LABEL_SIGNALLING_LEN      2
#define GTPV0_FLOW_LABEL_DATA_II             0x12
#define GTPV0_FLOW_LABEL_DATA_II_LEN         3
#define GTPV0_MS_NOT_REACHABLE_REASON        0x13
#define GTPV0_MS_NOT_REACHABLE_REASON_LEN    1
#define GTPV0_CHARGING_ID                    0x7F
#define GTPV0_CHARGING_ID_LEN                4

#define GTPV0_END_USER_ADDRESS               0x80
#define GTPV0_MM_CONTEXT                     0x81
#define GTPV0_PDP_CONTEXT                    0x82
#define GTPV0_ACCESS_POINT_NAME              0x83
#define GTPV0_PROTOCOL_CONFIGURATION_OPTIONS 0x84
#define GTPV0_GSN_ADDRESS                    0x85
#define GTPV0_MS_INTERNATIONAL_NUMBER        0x86
#define GTPV0_CHARGING_GATEWAY_ADDRESS       0xFB
#define GTPV0_PRIVATE_EXTENSION              0xFF

/* TV parser */
#define defFallbackTv(name)                                          \
  static int skip##name(uint8_t *data, uint32_t datalen, gtp_t *gtp) \
  {                                                                  \
    (void)gtp; /* suppress warnings for unused parameter */          \
    if (data[0] != GTPV0_##name) {                                   \
      return 0;                                                      \
    }                                                                \
    if (datalen < GTPV0_##name##_LEN + 1) {                          \
      return -1;                                                     \
    }                                                                \
                                                                     \
    return 1 + GTPV0_##name##_LEN;                                   \
  }

/* define fallback tv */
// clang-format off
defFallbackTv(TLLI)
defFallbackTv(P_TMSI)
defFallbackTv(AUTHENTICATION_TRIPLET)
defFallbackTv(MAP_CAUSE)
defFallbackTv(P_TMSI_SIGNATURE)
defFallbackTv(MS_VALIDATED)
defFallbackTv(FLOW_LABEL_DATA_II)
defFallbackTv(MS_NOT_REACHABLE_REASON)

#undef defFallbackTv

static int decodeCause(uint8_t *data, uint32_t datalen,
                       gtp_t *gtp)
{
    if (data[0] != GTPV0_CAUSE) {
        return 0;
    }
    if (datalen < GTPV0_CAUSE_LEN + 1) {
        return -1;
    }

    gtp->b0.cause = data[1];
    return 1 + GTPV0_CAUSE_LEN;
}
// clang-format on

/*
 * @return 
 *   -1 error
 *   0 not found IE
 */
static int decodeImsi(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_IMSI) {
        return 0;
    }
    if (datalen < GTPV0_IMSI_LEN + 1) {
        return -1;
    }

    BCD2ASCII(data + 1, GTPV0_IMSI_LEN * 2, gtp->b0.imsi, MAX_IMSI_BCD_LEN + 1);
    return 1 + GTPV0_IMSI_LEN;
}

static int decodeRoutingAreaIdentity(uint8_t *data, uint32_t datalen,
                                     gtp_t *gtp)
{
    if (data[0] != GTPV0_ROUTING_AREA_IDENTITY) {
        return 0;
    }
    if (datalen < GTPV0_ROUTING_AREA_IDENTITY_LEN + 1) {
        return -1;
    }

    int offset = 1;
    offset += decodeMccMncLac(data + offset, gtp->b0.routingAreaIdentityMcc,
                              gtp->b0.routingAreaIdentityMnc,
                              &gtp->b0.routingAreaIdentityLac);
    gtp->b0.routingAreaIdentityRac = data[offset];
    offset += 1;

    return offset;
}

static int decodeQos(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_QUALITY_OF_SERVICE) {
        return 0;
    }
    if (datalen < GTPV0_QUALITY_OF_SERVICE_LEN + 1) {
        return -1;
    }

    int offset = 1;
    memcpy(gtp->b0.qos, data + offset, GTPV0_QUALITY_OF_SERVICE_LEN);
    offset += GTPV0_QUALITY_OF_SERVICE_LEN;
    return offset;
}

static int decodeReorderingRequired(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_REORDERING_REQUIRED) {
        return 0;
    }
    if (datalen < GTPV0_REORDERING_REQUIRED_LEN + 1) {
        return -1;
    }

    gtp->b0.reordering = data[1];
    return 1 + GTPV0_REORDERING_REQUIRED_LEN;
}

static int decodeRecovery(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_RECOVERY) {
        return 0;
    }
    if (datalen < GTPV0_RECOVERY_LEN + 1) {
        return -1;
    }

    gtp->b0.recovery = data[1];
    return 1 + GTPV0_RECOVERY_LEN;
}

static int decodeSelectionMode(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_SELECTION_MODE) {
        return 0;
    }
    if (datalen < GTPV0_SELECTION_MODE_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b0.selectionMode = data[offset] & 0x03;
    offset += GTPV0_SELECTION_MODE_LEN;

    return offset;
}

static int decodeFlowLabelDataI(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_FLOW_LABEL_DATA_I) {
        return 0;
    }
    if (datalen < GTPV0_FLOW_LABEL_DATA_I_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b0.flowLabelData = ntohs(*(uint16_t *)(data + offset));
    offset += GTPV0_FLOW_LABEL_DATA_I_LEN;
    return offset;
}

static int decodeFlowLabelSignalling(uint8_t *data, uint32_t datalen,
                                     gtp_t *gtp)
{
    if (data[0] != GTPV0_FLOW_LABEL_SIGNALLING) {
        return 0;
    }
    if (datalen < GTPV0_FLOW_LABEL_SIGNALLING_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b0.flowLabelSignalling = ntohs(*(uint16_t *)(data + offset));
    offset += GTPV0_FLOW_LABEL_SIGNALLING_LEN;
    return offset;
}

static int decodeChargingID(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV0_CHARGING_ID) {
        return 0;
    }
    if (datalen < GTPV0_CHARGING_ID_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b0.chargingId = ntohl(*(uint32_t *)(data + offset));
    offset += GTPV0_CHARGING_ID_LEN;
    return offset;
}

static inline int decodeGtpV0Tlv(uint8_t *data, uint32_t datalen, uint8_t type,
                                 uint8_t **out, int *outlen)
{
    uint32_t offset = 0;
    *outlen = 0;
    if (data[0] == type) {
        int length = ntohs(*(uint16_t *)&data[1]);
        offset = length + 3;
        if (datalen < offset) {
            return -1;
        }
        *out = data + 3;
        *outlen = length;
    }

    return offset;
}

static int decodeEndUserAddress(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV0Tlv(data, datalen, GTPV0_END_USER_ADDRESS, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    gtp->b0.pdpTypeOrg = p_value[0] & 0x0F;
    gtp->b0.pdpTypeNum = p_value[1];
    if (p_value_len == 2) {
    } else if (p_value_len == 6) {
        inet_ntop(AF_INET, p_value + 2, gtp->b0.endUserAddress, 16);
    } else if (p_value_len == 18) {
        inet_ntop(AF_INET6, p_value + 2, gtp->b0.endUserAddress, 40);
    } else if (p_value_len == 22) {
        inet_ntop(AF_INET, p_value + 2, gtp->b0.endUserAddress, 16);
        // we discard ipv6?
    } else {
        printf("weired End User Address Length[%d]\n", p_value_len);
    }
    return ret;
}

static int decodeAccessPointName(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV0Tlv(data, datalen, GTPV0_ACCESS_POINT_NAME, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }
    if (p_value_len >= MAX_APN_LEN) {
        return -1;
    }

    int offset = 0;
    // remove prefix character
    while (p_value[offset] < 0x20 && offset < p_value_len) {
        offset++;
    }
    strncpy(gtp->b0.apn, (char *)(p_value + offset), p_value_len - offset);
    for (int i = 0; i < MAX_APN_LEN; i++) {
        if (gtp->b0.apn[i] == 0) {
            break;
        }
        // convert unprintable character
        if (gtp->b0.apn[i] < 32) gtp->b0.apn[i] = '.';
    }
    return ret;
}

static int decodeProtocolConfOpts(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret =
        decodeGtpV0Tlv(data, datalen, GTPV0_PROTOCOL_CONFIGURATION_OPTIONS,
                       &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    // decode Protocol configuration options
    return ret;
}

static int decodeGSNAddress(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV0Tlv(data, datalen, GTPV0_GSN_ADDRESS, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    char *ip = gtp->b0.gsnAddressSignal;
    if (strlen(ip)) {
        ip = gtp->b0.gsnAddressUser;
    }
    if (p_value_len == 4) {
        inet_ntop(AF_INET, p_value, ip, 16);
    } else if (p_value_len == 6) {
        inet_ntop(AF_INET6, p_value, ip, 40);
    } else {
        printf("weired GSN Address length[%d]\n", p_value_len);
    }
    return ret;
}

static int decodeMSInternationalNumber(uint8_t *data, uint32_t datalen,
                                       gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV0Tlv(data, datalen, GTPV0_MS_INTERNATIONAL_NUMBER,
                             &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    // uint8_t msisdnFlag = p_value[0];
    BCD2ASCII(p_value + 1, (p_value_len - 1) * 2, gtp->b0.msisdn,
              MAX_MSISDN_BCD_LEN + 1);
    return ret;
}

int registerGtpv0IEParsers(onIEParse ietable[MAX_IE])
{
    ietable[GTPV0_CAUSE] = decodeCause;
    ietable[GTPV0_IMSI] = decodeImsi;
    ietable[GTPV0_ROUTING_AREA_IDENTITY] = decodeRoutingAreaIdentity;
    ietable[GTPV0_TLLI] = skipTLLI;
    ietable[GTPV0_P_TMSI] = skipP_TMSI;
    ietable[GTPV0_QUALITY_OF_SERVICE] = decodeQos;

    ietable[GTPV0_REORDERING_REQUIRED] = decodeReorderingRequired;
    ietable[GTPV0_AUTHENTICATION_TRIPLET] = skipAUTHENTICATION_TRIPLET;

    ietable[GTPV0_MAP_CAUSE] = skipMAP_CAUSE;
    ietable[GTPV0_P_TMSI_SIGNATURE] = skipP_TMSI_SIGNATURE;
    ietable[GTPV0_MS_VALIDATED] = skipMS_VALIDATED;
    ietable[GTPV0_RECOVERY] = decodeRecovery;
    ietable[GTPV0_SELECTION_MODE] = decodeSelectionMode;
    ietable[GTPV0_FLOW_LABEL_DATA_I] = decodeFlowLabelDataI;
    ietable[GTPV0_FLOW_LABEL_SIGNALLING] = decodeFlowLabelSignalling;
    ietable[GTPV0_FLOW_LABEL_DATA_II] = skipFLOW_LABEL_DATA_II;
    ietable[GTPV0_MS_NOT_REACHABLE_REASON] = skipMS_NOT_REACHABLE_REASON;
    ietable[GTPV0_CHARGING_ID] = decodeChargingID;
    ietable[GTPV0_END_USER_ADDRESS] = decodeEndUserAddress;
    ietable[GTPV0_ACCESS_POINT_NAME] = decodeAccessPointName;
    ietable[GTPV0_PROTOCOL_CONFIGURATION_OPTIONS] = decodeProtocolConfOpts;
    ietable[GTPV0_GSN_ADDRESS] = decodeGSNAddress;
    ietable[GTPV0_MS_INTERNATIONAL_NUMBER] = decodeMSInternationalNumber;

    // todo: add validation for TV registration
    return 1;
}
