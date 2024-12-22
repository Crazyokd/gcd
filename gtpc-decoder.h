#ifndef GTPC_DECODER_H_
#define GTPC_DECODER_H_

#include <stdint.h>

#include "macros.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gtp_header_s {
    uint8_t version;
    uint8_t msgType;
    uint16_t msgLen;
    uint32_t teid;
    uint32_t sqn;
} gtp_header_t;

#define BCD_TO_BUFFER_LEN(x) (((x) + 1) / 2)
#define MAX_IMSI_BCD_LEN     15
#define MAX_IMSI_LEN         BCD_TO_BUFFER_LEN(MAX_IMSI_BCD_LEN)

#define MAX_IMEISV_BCD_LEN   16
#define MAX_IMEISV_LEN       BCD_TO_BUFFER_LEN(MAX_IMEISV_BCD_LEN)

#define MAX_MSISDN_BCD_LEN   15
#define MAX_MSISDN_LEN       BCD_TO_BUFFER_LEN(MAX_MSISDN_BCD_LEN)

#define MAX_APN_LEN          100

#define MAX_IP_SIZE          39 // 16*2 + 7

typedef struct gtp_v0_body_s {
#define GTPV0_CAUSE_REQUEST_IMSI 0
#define GTPV0_CAUSE_REQUEST_IMEI 1
    uint8_t cause;
    char imsi[MAX_IMSI_BCD_LEN + 1];
    char routingAreaIdentityMcc[MAX_MCC_SIZE + 1]; // eg. 460
    char routingAreaIdentityMnc[MAX_MNC_SIZE + 1]; // eg. 00
    uint16_t routingAreaIdentityLac;
    uint8_t routingAreaIdentityRac;
    uint8_t qos[3];
    /*
     * 0 NO
     * 1 YES
     */
    uint8_t reordering;
    uint8_t recovery;
    /*
     * selection mode values:
     * 0 MS or network provided APN, subscribed verified
     * 1 MS provided APN, subscription not verified
     * 2 Network provided APN, subscription not verified
     * 3 For future use. Shall not be sent. If received, shall be interpreted as the value ‘2’
     */
    uint8_t selectionMode;
    uint16_t flowLabelData;
    uint16_t flowLabelSignalling;
    uint8_t msNotReachableReason;
    uint32_t chargingId;

    /* tlv field */
    /*
     * 0 ETSI
     * 1 IETE
     */
    uint8_t pdpTypeOrg;
    uint8_t pdpTypeNum;
    char endUserAddress[MAX_IP_SIZE];
    char apn[MAX_APN_LEN + 1];
    char gsnAddressSignal[MAX_IP_SIZE + 1];
    char gsnAddressUser[MAX_IP_SIZE + 1];
    char msisdn[MAX_MSISDN_BCD_LEN + 1];
} gtp_v0_body_t;

typedef struct gtp_v1_body_s {
#define GTPV1_CAUSE_REQUEST_IMSI 0
#define GTPV1_CAUSE_REQUEST_IMEI 1
    uint8_t cause;
    char imsi[MAX_IMSI_BCD_LEN + 1];
    char routingAreaIdentityMcc[MAX_MCC_SIZE + 1]; // eg. 460
    char routingAreaIdentityMnc[MAX_MNC_SIZE + 1]; // eg. 00
    uint16_t routingAreaIdentityLac;
    uint8_t routingAreaIdentityRac;
    /*
     * 0 NO
     * 1 YES
     */
    uint8_t reordering;
    uint8_t recovery;
    /*
     * selection mode values:
     * 0 MS or network provided APN, subscribed verified
     * 1 MS provided APN, subscription not verified
     * 2 Network provided APN, subscription not verified
     * 3 For future use. Shall not be sent. If received, shall be interpreted as the value ‘2’
     */
    uint8_t selectionMode;
    uint32_t teid;
    uint32_t teidControlPlane;
    /**
     * No  0
     * Yes 1
     */
    uint8_t teardownInd;
    uint8_t nsapi;
    uint8_t ranapCause;
    uint8_t chargingFlags; // from Charging characteristics
    uint32_t chargingId;

    /* tlv field */
    /*
     * 0 ETSI
     * 1 IETE
     */
    uint8_t pdpTypeOrg;
    uint8_t pdpTypeNum;
    char endUserAddress[MAX_IP_SIZE];
    char apn[MAX_APN_LEN + 1];
    char gsnAddressSignal[MAX_IP_SIZE + 1];
    char gsnAddressUser[MAX_IP_SIZE + 1];
    char msisdn[MAX_MSISDN_BCD_LEN + 1];
    uint8_t priority; // allocatoin/retention of qos
    uint8_t commonFlags;
    uint8_t ratType;
    char userLocationInforMcc[MAX_MCC_SIZE + 1];
    char userLocationInforMnc[MAX_MNC_SIZE + 1];
    unsigned short userLocationInforLac;
    uint16_t userLocationInforCellId;
    uint8_t timezone;
    uint8_t dst;
    char imei[MAX_IMEISV_BCD_LEN + 1];
    uint8_t bearerControlMode;
} gtp_v1_body_t;
typedef struct gtp_v2_body_s {
    char imsi[MAX_IMSI_BCD_LEN + 1];
    uint32_t teid;
} gtp_v2_body_t;

typedef struct gtp_s {
    gtp_header_t hdr;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    union {
        gtp_v0_body_t b0;
        gtp_v1_body_t b1;
        gtp_v2_body_t b2;
    };
#pragma GCC diagnostic pop

} gtp_t;

#define MAX_IE 0xFF
typedef int (*onIEParse)(uint8_t *data, uint32_t len, gtp_t *body);

/**
 * init all IEs
 * @return
 *   1  success
 *   0  error
 */
GCD_PUBLIC int initIEParsers();
/**
 * register your custom IE
 * @return
 *   -1 error
 *   0  add a new IEParser
 *   1  replace an existing IEParser
 */
GCD_PUBLIC int registerIEParser(uint8_t version, uint8_t ie, onIEParse parser);
/**
 * decode gtpc data
 * @return
 *   -1 on decode header error or not supported version
 *   0  on decode body error
 *   1  on success
 */
GCD_PUBLIC int decodeGtpc(uint8_t *data, uint32_t len, gtp_t *gtp);

#ifdef __cplusplus
}
#endif

#endif
