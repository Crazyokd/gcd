#ifndef GTP_UTIL_H_
#define GTP_UTIL_H_

#include <stdint.h>

uint8_t BCD2ASCII(uint8_t *bcd, uint8_t bcdLen, char *ascii, uint8_t asciiLen);
int decodeMccMncLac(uint8_t *data, char *mcc, char *mnc, uint16_t *lac);

#endif
