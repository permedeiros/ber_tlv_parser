/**
 * @file
 * @brief Header file of BER-TLV parser lib
 * @author Pedro Eugênio Rocha Medeiros
 * @date 14/10/2021
 */

#ifndef __BER_TLV_H
#define __BER_TLV_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief BER TLV object
 */
typedef struct
{
    //! tag value
    uint16_t tag; 
    //! size of tag field in bytes
    uint16_t tagSize;
    //! Length field value
    uint32_t lengthValue; 
    //! Size of length field in bytes
    uint8_t lengthSize;
    //! Size of value field in byts
    uint16_t valueSize;
    //! Pointer to the value field
    uint8_t * value;
} TBerTlvObj;


/**
 * Prints raw data as BER TLV objects
 * @param data pointer to raw data.
 * @param size Data size in bytes.
 * @param outputStr pointer to output string.
 * @return Total bytes writen.
 */
uint16_t berTlv_printFromRawData(uint8_t *data, uint16_t size, char *outputStr);

/**
 * @brief Parse an raw data array.
 * @warning: As garbage data is allowed before, between and after tlv objects, this function will 
 * skip garbage data and update size accordingly.
 * @param data Raw data pointer
 * @param size Data size in bytes
 * @param tlvObjOut Pointer to tlv object that will be filled with parsed data.
 * @param isNotInConstructedObject  Infors if the current object is within a constructed object.
 * @return true if an error happened during the data parsing.
 */
bool berTlv_parseRawData(uint8_t *data, uint16_t *size, TBerTlvObj *tlvObjOut, bool isNotInConstructedObject);


#endif

