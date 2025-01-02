#include "gtpv1-decoder.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

/* below macro are based on ts 29.060 */
#define GTPV1_RESERVED                        0x0
#define GTPV1_CAUSE                           0x01
#define GTPV1_CAUSE_LEN                       1
#define GTPV1_IMSI                            0x02
#define GTPV1_IMSI_LEN                        8
#define GTPV1_ROUTING_AREA_IDENTITY           0x03
#define GTPV1_ROUTING_AREA_IDENTITY_LEN       6
#define GTPV1_TLLI                            0x04
#define GTPV1_TLLI_LEN                        4
#define GTPV1_P_TMSI                          0x05
#define GTPV1_P_TMSI_LEN                      4
// 6-7 spare
#define GTPV1_REORDERING_REQUIRED             0x08
#define GTPV1_REORDERING_REQUIRED_LEN         1
#define GTPV1_AUTHENTICATION_TRIPLET          0x09
#define GTPV1_AUTHENTICATION_TRIPLET_LEN      28
// 10 spare
#define GTPV1_MAP_CAUSE                       0x0B
#define GTPV1_MAP_CAUSE_LEN                   1
#define GTPV1_P_TMSI_SIGNATURE                0x0C
#define GTPV1_P_TMSI_SIGNATURE_LEN            3
#define GTPV1_MS_VALIDATED                    0x0D
#define GTPV1_MS_VALIDATED_LEN                1
#define GTPV1_RECOVERY                        0x0e
#define GTPV1_RECOVERY_LEN                    1
#define GTPV1_SELECTION_MODE                  0x0F
#define GTPV1_SELECTION_MODE_LEN              1
#define GTPV1_TEID_DATA_I                     0x10
#define GTPV1_TEID_DATA_I_LEN                 4
#define GTPV1_TEID_CONTROL_PLANE              0x11
#define GTPV1_TEID_CONTROL_PLANE_LEN          4
#define GTPV1_TEID_DATA_II                    0x12
#define GTPV1_TEID_DATA_II_LEN                5
#define GTPV1_TEARDOWN_IND                    0x13
#define GTPV1_TEARDOWN_IND_LEN                1
#define GTPV1_NSAPI                           0x14
#define GTPV1_NSAPI_LEN                       1
#define GTPV1_RANAP_CAUSE                     0x15
#define GTPV1_RANAP_CAUSE_LEN                 1
#define GTPV1_RAB_CONTEXT                     22
#define GTPV1_RAB_CONTEXT_LEN                 9
#define GTPV1_RADIO_PRIORITY_SMS              23
#define GTPV1_RADIO_PRIORITY_SMS_LEN          1
#define GTPV1_RADIO_PRIORITY                  24
#define GTPV1_RADIO_PRIORITY_LEN              1
#define GTPV1_PACKET_FLOW_ID                  0x19
#define GTPV1_PACKET_FLOW_ID_LEN              2
#define GTPV1_CHARGING_CHARACTERISTICS        0x1A
#define GTPV1_CHARGING_CHARACTERISTICS_LEN    2
#define GTPV1_TRACE_REFERENCE                 0x1B
#define GTPV1_TRACE_REFERENCE_LEN             2
#define GTPV1_TRACE_TYPE                      0x1C
#define GTPV1_TRACE_TYPE_LEN                  2
#define GTPV1_MS_NOT_REACHABLE_REASON         0x1D
#define GTPV1_MS_NOT_REACHABLE_REASON_LEN     1
// 30-116 Reserved(No TV types can now be allocated)
// 117-126 (Reserved for the GPRS charging protocol)
#define GTPV1_CHARGING_ID                     0x7F
#define GTPV1_CHARGING_ID_LEN                 4

#define GTPV1_END_USER_ADDRESS                0x80
#define GTPV1_ACCESS_POINT_NAME               0x83
#define GTPV1_PROTOCOL_CONFIGURATION_OPTIONS  0x84
#define GTPV1_GSN_ADDRESS                     0x85
#define GTPV1_MS_INTERNATIONAL_NUMBER         0x86
#define GTPV1_QUALITY_OF_SERVICE              0x87
#define GTPV1_COMMON_FLAGS                    0x94
#define GTPV1_RAT_TYPE                        0x97
#define GTPV1_USER_LOCATION_INFORMATION       0x98
#define GTPV1_MS_TIME_ZONE                    0x99
#define GTPV1_IMEI                            0x9a
#define GTPV1_MS_INFO_CHANGE_REPORTING_ACTION 0xB5
#define GTPV1_BEARER_CONTROL_MODE             0xB8
#define GTPV1_EVOLVED_PRIORITY_I              0xBF

/* TV parser */
#define defFallbackTv(name)                                          \
  static int skip##name(uint8_t *data, uint32_t datalen, gtp_t *gtp) \
  {                                                                  \
    (void)gtp; /* suppress warnings for unused parameter */          \
    if (data[0] != GTPV1_##name) {                                   \
      return 0;                                                      \
    }                                                                \
    if (datalen < GTPV1_##name##_LEN + 1) {                          \
      return -1;                                                     \
    }                                                                \
                                                                     \
    return 1 + GTPV1_##name##_LEN;                                   \
  }

/* define fallback tv */
// clang-format off
defFallbackTv(TLLI)
defFallbackTv(P_TMSI)
defFallbackTv(AUTHENTICATION_TRIPLET)
defFallbackTv(MAP_CAUSE)
defFallbackTv(P_TMSI_SIGNATURE)
defFallbackTv(MS_VALIDATED)
defFallbackTv(TEID_DATA_II)
defFallbackTv(RANAP_CAUSE)
defFallbackTv(RAB_CONTEXT)
defFallbackTv(RADIO_PRIORITY_SMS)
defFallbackTv(RADIO_PRIORITY)
defFallbackTv(PACKET_FLOW_ID)
defFallbackTv(TRACE_REFERENCE)
defFallbackTv(TRACE_TYPE)
defFallbackTv(MS_NOT_REACHABLE_REASON)

#undef defFallbackTv

static int decodeCause(uint8_t *data, uint32_t datalen,
                       gtp_t *gtp)
{
    if (data[0] != GTPV1_CAUSE) {
        return 0;
    }
    if (datalen < GTPV1_CAUSE_LEN + 1) {
        return -1;
    }

    gtp->b1.cause = data[1];
    return 1 + GTPV1_CAUSE_LEN;
}
// clang-format on

/*
 * @return 
 *   -1 error
 *   0 not found IE
 */
static int decodeImsi(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_IMSI) {
        return 0;
    }
    if (datalen < GTPV1_IMSI_LEN + 1) {
        return -1;
    }

    BCD2ASCII(data + 1, GTPV1_IMSI_LEN * 2, gtp->b1.imsi, MAX_IMSI_BCD_LEN + 1);
    return 1 + GTPV1_IMSI_LEN;
}

static int decodeRoutingAreaIdentity(uint8_t *data, uint32_t datalen,
                                     gtp_t *gtp)
{
    if (data[0] != GTPV1_ROUTING_AREA_IDENTITY) {
        return 0;
    }
    if (datalen < GTPV1_ROUTING_AREA_IDENTITY_LEN + 1) {
        return -1;
    }

    int offset = 1;
    offset += decodeMccMncLac(data + offset, gtp->b1.routingAreaIdentityMcc,
                              gtp->b1.routingAreaIdentityMnc,
                              &gtp->b1.routingAreaIdentityLac);
    gtp->b1.routingAreaIdentityRac = data[offset];
    offset += 1;

    return offset;
}

static int decodeReorderingRequired(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_REORDERING_REQUIRED) {
        return 0;
    }
    if (datalen < GTPV1_REORDERING_REQUIRED_LEN + 1) {
        return -1;
    }

    gtp->b1.reordering = data[1];
    return 1 + GTPV1_REORDERING_REQUIRED_LEN;
}

static int decodeRecovery(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_RECOVERY) {
        return 0;
    }
    if (datalen < GTPV1_RECOVERY_LEN + 1) {
        return -1;
    }

    gtp->b1.recovery = data[1];
    return 1 + GTPV1_RECOVERY_LEN;
}

static int decodeSelectionMode(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_SELECTION_MODE) {
        return 0;
    }
    if (datalen < GTPV1_SELECTION_MODE_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.selectionMode = data[offset] & 0x03;
    offset += GTPV1_SELECTION_MODE_LEN;

    return offset;
}

static int decodeTEIDDataI(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_TEID_DATA_I) {
        return 0;
    }
    if (datalen < GTPV1_TEID_DATA_I_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.teid = ntohl(*(uint32_t *)(data + offset));
    offset += GTPV1_TEID_DATA_I_LEN;
    return offset;
}

static int decodeTEIDControlPlane(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_TEID_CONTROL_PLANE) {
        return 0;
    }
    if (datalen < GTPV1_TEID_CONTROL_PLANE_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.teidControlPlane = ntohl(*(uint32_t *)(data + offset));
    offset += GTPV1_TEID_CONTROL_PLANE_LEN;
    return offset;
}

static int decodeTeardownInd(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_TEARDOWN_IND) {
        return 0;
    }
    if (datalen < GTPV1_TEARDOWN_IND_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.teardownInd = data[offset] & 0x01;
    offset += GTPV1_TEARDOWN_IND_LEN;
    return offset;
}

static int decodeNSAPI(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_NSAPI) {
        return 0;
    }
    if (datalen < GTPV1_NSAPI_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.nsapi = data[offset] & 0x0F;
    offset += GTPV1_NSAPI_LEN;
    return offset;
}

static int decodeChargingCharacteristics(uint8_t *data, uint32_t datalen,
                                         gtp_t *gtp)
{
    if (data[0] != GTPV1_CHARGING_CHARACTERISTICS) {
        return 0;
    }
    if (datalen < GTPV1_CHARGING_CHARACTERISTICS_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.chargingFlags = data[offset] & 0x0F;
    offset += GTPV1_CHARGING_CHARACTERISTICS_LEN;
    return offset;
}

static int decodeChargingID(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    if (data[0] != GTPV1_CHARGING_ID) {
        return 0;
    }
    if (datalen < GTPV1_CHARGING_ID_LEN + 1) {
        return -1;
    }

    int offset = 1;
    gtp->b1.chargingId = ntohl(*(uint32_t *)(data + offset));
    offset += GTPV1_CHARGING_ID_LEN;
    return offset;
}

/* TLV parser */
static inline int decodeGtpV1Tlv(uint8_t *data, uint32_t datalen, uint8_t type,
                                 uint8_t **out, int *outlen)
{
    uint32_t offset = 0;
    *outlen = 0;
    if (data[0] == type) {
        uint16_t length = ntohs(*(uint16_t *)&data[1]);
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
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_END_USER_ADDRESS, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    gtp->b1.pdpTypeOrg = p_value[0] & 0x0F;
    gtp->b1.pdpTypeNum = p_value[1];
    if (p_value_len == 2) {
    } else if (p_value_len == 6) {
        inet_ntop(AF_INET, p_value + 2, gtp->b1.endUserAddress, 16);
    } else if (p_value_len == 18) {
        inet_ntop(AF_INET6, p_value + 2, gtp->b1.endUserAddress, 40);
    } else if (p_value_len == 22) {
        inet_ntop(AF_INET, p_value + 2, gtp->b1.endUserAddress, 16);
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
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_ACCESS_POINT_NAME, &p_value,
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
    strncpy(gtp->b1.apn, (char *)(p_value + offset), p_value_len - offset);
    for (int i = 0; i < MAX_APN_LEN; i++) {
        if (gtp->b1.apn[i] == 0) {
            break;
        }
        // convert unprintable character
        if (gtp->b1.apn[i] < 32) gtp->b1.apn[i] = '.';
    }
    return ret;
}

static int decodeProtocolConfOpts(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret =
        decodeGtpV1Tlv(data, datalen, GTPV1_PROTOCOL_CONFIGURATION_OPTIONS,
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
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_GSN_ADDRESS, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    char *ip = gtp->b1.gsnAddressSignal;
    if (strlen(ip)) {
        ip = gtp->b1.gsnAddressUser;
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
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_MS_INTERNATIONAL_NUMBER,
                             &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    // uint8_t msisdnFlag = p_value[0];
    BCD2ASCII(p_value + 1, (p_value_len - 1) * 2, gtp->b1.msisdn,
              MAX_MSISDN_BCD_LEN + 1);
    return ret;
}

static int decodeqos(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_QUALITY_OF_SERVICE, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    gtp->b1.priority = p_value[0];
    // decode qos params
    return ret;
}

static int decodeCommonFlags(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_COMMON_FLAGS, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    gtp->b1.commonFlags = p_value[0];
    return ret;
}

static int decodeRATType(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret =
        decodeGtpV1Tlv(data, datalen, GTPV1_RAT_TYPE, &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    /*
     * 2 GERAN
     */
    gtp->b1.ratType = p_value[0];
    return ret;
}

static int decodeUserLocationInformation(uint8_t *data, uint32_t datalen,
                                         gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_USER_LOCATION_INFORMATION,
                             &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    uint8_t geographicLocationType = p_value[0];
    int offset = 1;
    switch (geographicLocationType) {
    case 0: {
        offset += decodeMccMncLac(
            p_value + offset, gtp->b1.userLocationInforMcc,
            gtp->b1.userLocationInforMnc, &gtp->b1.userLocationInforLac);
        gtp->b1.userLocationInforCellId =
            ntohs(*(uint16_t *)(p_value + offset));
        offset += 2;
        break;
    }

    default:
        break;
    }
    return ret;
}

static int decodeMSTimeZone(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_MS_TIME_ZONE, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    gtp->b1.timezone = p_value[0];
    gtp->b1.dst = p_value[1] & 0x03;
    return ret;
}

static int decodeIMEI(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_IMEI, &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    BCD2ASCII(p_value, p_value_len * 2, gtp->b1.imei, MAX_IMEISV_BCD_LEN);
    return ret;
}

static int decodeMSInfoChangeReportingAction(uint8_t *data, uint32_t datalen,
                                             gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret =
        decodeGtpV1Tlv(data, datalen, GTPV1_MS_INFO_CHANGE_REPORTING_ACTION,
                       &p_value, &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    // uint8_t action = p_value[0];
    return ret;
}

static int decodeBearerControlMode(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_BEARER_CONTROL_MODE, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    gtp->b1.bearerControlMode = p_value[0];
    return ret;
}

static int decodeEPriorityI(uint8_t *data, uint32_t datalen, gtp_t *gtp)
{
    uint8_t *p_value = NULL;
    int p_value_len = 0;
    int ret = decodeGtpV1Tlv(data, datalen, GTPV1_EVOLVED_PRIORITY_I, &p_value,
                             &p_value_len);
    if (ret <= 0) {
        return ret;
    }

    // 1B: PCI + PL + PVI
    return ret;
}

int registerGtpv1IEParsers(onIEParse ietable[MAX_IE])
{
    ietable[GTPV1_CAUSE] = decodeCause;
    ietable[GTPV1_IMSI] = decodeImsi;
    ietable[GTPV1_ROUTING_AREA_IDENTITY] = decodeRoutingAreaIdentity;
    ietable[GTPV1_TLLI] = skipTLLI;
    ietable[GTPV1_P_TMSI] = skipP_TMSI;
    ietable[GTPV1_REORDERING_REQUIRED] = decodeReorderingRequired;
    ietable[GTPV1_AUTHENTICATION_TRIPLET] = skipAUTHENTICATION_TRIPLET;
    ietable[GTPV1_MAP_CAUSE] = skipMAP_CAUSE;
    ietable[GTPV1_P_TMSI_SIGNATURE] = skipP_TMSI_SIGNATURE;
    ietable[GTPV1_MS_VALIDATED] = skipMS_VALIDATED;
    ietable[GTPV1_RECOVERY] = decodeRecovery;
    ietable[GTPV1_SELECTION_MODE] = decodeSelectionMode;
    ietable[GTPV1_TEID_DATA_I] = decodeTEIDDataI;
    ietable[GTPV1_TEID_CONTROL_PLANE] = decodeTEIDControlPlane;
    ietable[GTPV1_TEID_DATA_II] = skipTEID_DATA_II;
    ietable[GTPV1_TEARDOWN_IND] = decodeTeardownInd;
    ietable[GTPV1_NSAPI] = decodeNSAPI;
    ietable[GTPV1_RANAP_CAUSE] = skipRANAP_CAUSE;
    ietable[GTPV1_RAB_CONTEXT] = skipRAB_CONTEXT;
    ietable[GTPV1_RADIO_PRIORITY_SMS] = skipRADIO_PRIORITY_SMS;
    ietable[GTPV1_RADIO_PRIORITY] = skipRADIO_PRIORITY;
    ietable[GTPV1_PACKET_FLOW_ID] = skipPACKET_FLOW_ID;
    ietable[GTPV1_CHARGING_CHARACTERISTICS] = decodeChargingCharacteristics;
    ietable[GTPV1_TRACE_REFERENCE] = skipTRACE_REFERENCE;
    ietable[GTPV1_TRACE_TYPE] = skipTRACE_TYPE;
    ietable[GTPV1_MS_NOT_REACHABLE_REASON] = skipMS_NOT_REACHABLE_REASON;
    ietable[GTPV1_CHARGING_ID] = decodeChargingID;
    ietable[GTPV1_END_USER_ADDRESS] = decodeEndUserAddress;
    ietable[GTPV1_ACCESS_POINT_NAME] = decodeAccessPointName;
    ietable[GTPV1_PROTOCOL_CONFIGURATION_OPTIONS] = decodeProtocolConfOpts;
    ietable[GTPV1_MS_INTERNATIONAL_NUMBER] = decodeMSInternationalNumber;
    ietable[GTPV1_IMEI] = decodeIMEI;
    ietable[GTPV1_GSN_ADDRESS] = decodeGSNAddress;
    ietable[GTPV1_QUALITY_OF_SERVICE] = decodeqos;
    ietable[GTPV1_COMMON_FLAGS] = decodeCommonFlags;
    ietable[GTPV1_RAT_TYPE] = decodeRATType;
    ietable[GTPV1_USER_LOCATION_INFORMATION] = decodeUserLocationInformation;
    ietable[GTPV1_MS_TIME_ZONE] = decodeMSTimeZone;
    ietable[GTPV1_EVOLVED_PRIORITY_I] = decodeEPriorityI;
    ietable[GTPV1_BEARER_CONTROL_MODE] = decodeBearerControlMode;
    ietable[GTPV1_MS_INFO_CHANGE_REPORTING_ACTION] =
        decodeMSInfoChangeReportingAction;

    // todo: add validation for TV registration
    return 1;
}
