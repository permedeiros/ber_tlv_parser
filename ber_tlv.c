#include "ber_tlv.h"

#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

//! Non fatal assertion macro.
#define BER_TLV_ASSERT_NON_FATAL(cond, format, args...)         \
    if (!(cond))                                                \
    {                                                           \
        printf("ERROR: Fatal error in %s:%d %s()\n\n\t" format, \
               __FILE__,                                        \
               __LINE__,                                        \
               __FUNCTION__,                                    \
               ##args);                                         \
        printf("\n\n");                                         \
    }

//! Minimum header size in bytes
const uint8_t MIN_HEADER_SIZE = 2;

//! Bit position of TLV object class in the Tag field
const uint8_t TAG_CLASS_BIT_POS = 6;
//! Bit mas to extract the object class
const uint8_t TAG_CLASS_MASK = 0xC0;

//! Universal class
const uint8_t UNIVERSAL_CLASS = 0;
//! Application class
const uint8_t APPLICATION_CLASS = 1;
//! Context Specificc class
const uint8_t CONTEXT_SPECIFIC_CLASS = 2;
//! Private class
const uint8_t PRIVATE_CLASS = 3;

//! Object class string values
const char *BER_TLV_CLASSES[] = {"universal class",
                                 "application class",
                                 "context-specific class",
                                 "private class"};

//! Maskt to extract the tag size from first byte of the tag value
const uint8_t TWO_BYTES_TAG_MASK = 0x1F;

//! Bit position of object type (primitive or constructed) in first byte of tag field
const uint8_t TAG_OBJ_TYPE_BIT_POS = 5;
//! Mask to extract the object type value from the first byte of the tag field
const uint8_t TAG_OBJ_TYPE_MASk = 0x20;
//! Primitive data object type
const uint8_t PRIMITIVE_DATA_OBJECT = 0;
//! Constructed data object type
const uint8_t CONSTRUCTED_DATA_OBJECT = 1;
//! String definition of tlv object types
const char *BER_TLV_OBJECTS_TYPES[] = {"primitive",
                                       "constructed"};
//! Bit mask used to know if the lenght field has multiple bytes.
const uint8_t MULTPLES_BYTES_LENGTH_MASK = 0x80;

//------------------------------------------------Static fuctions definitions----------------------------------------------------//
static bool __isConstructed(TBerTlvObj *tlvObj);
static uint32_t __getValueSize(uint8_t *data);
static uint16_t __getLength(uint8_t *data);
static uint16_t __getLengthFieldSize(uint8_t *data);
static uint16_t __getTag(uint8_t *data);
static uint8_t __getTagSize(uint8_t fistTagByte);
static const char *__getObjTypeString(TBerTlvObj *tlvObj);
static const char *__getClassString(TBerTlvObj *tlvObj);
static uint8_t __getObjTypeIndex(uint8_t tagByte);
static uint8_t __getClassIndex(uint8_t tagByte);
static char *__addIndentation(char *str, uint16_t constructedLevels);

//-----------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------Public functions------------------------------------------------------//

void berTlv_printFromRawData(uint8_t *rawData, uint32_t size)
{
    TBerTlvObj tlvObj;
    char outputStr[4096];
    char *strP = outputStr;
    uint8_t *data = rawData;
    uint16_t remaningSize = size;

    uint16_t constructedSizeStack[5] = {0};
    uint8_t constructedLevels = 0;

    while (remaningSize)
    {
        bool err = berTlv_parseRawData(data, remaningSize, &tlvObj);
        if (err)
        {
            return;
        }
        strP = __addIndentation(strP, constructedLevels);
        strP += sprintf(strP, "TAG - 0x%02X (%s, %s)\n",
                        tlvObj.tag,
                        __getClassString(&tlvObj),
                        __getObjTypeString(&tlvObj));
        strP = __addIndentation(strP, constructedLevels);
        strP += sprintf(strP, "LEN - %d bytes\n", tlvObj.lengthValue);
        data = tlvObj.value;
        uint16_t headerSize = (tlvObj.tagSize + tlvObj.lengthSize);
        if (__isConstructed(&tlvObj))
        {
            remaningSize -= headerSize;
            if (constructedLevels)
            {
                constructedSizeStack[constructedLevels - 1] -= (+headerSize + tlvObj.valueSize);
                if (constructedSizeStack[constructedLevels - 1] == 0)
                {
                    constructedLevels--;
                }
            }
            constructedSizeStack[constructedLevels] = tlvObj.valueSize;
            constructedLevels++;
            strP += sprintf(strP, "\n");
        }
        else
        {
            uint16_t fullObjSize = headerSize + tlvObj.valueSize;
            remaningSize -= fullObjSize;
            if (tlvObj.valueSize)
            {
                strP = __addIndentation(strP, constructedLevels);
                strP += sprintf(strP, "VAL - ");
                for (int i = 0; i < tlvObj.valueSize; ++i)
                {
                    strP += sprintf(strP, "0x%02X ", *data++);
                }
                strP += sprintf(strP, "\n");
            }
            strP += sprintf(strP, "\n");

            if (constructedLevels)
            {
                constructedSizeStack[constructedLevels - 1] -= fullObjSize;
                if (constructedSizeStack[constructedLevels - 1] == 0)
                {
                    constructedLevels--;
                }
            }
        }
    }

    printf("%s\n", outputStr);
}

bool berTlv_parseRawData(uint8_t *data, uint32_t size, TBerTlvObj *tlvObjOut)
{
    uint8_t *dataP = data;
    uint8_t minHeaderSize = MIN_HEADER_SIZE;
    bool error = false;

    tlvObjOut->tagSize = __getTagSize(data[0]);

    if (tlvObjOut->tagSize == 2)
    {
        minHeaderSize += 1;
    }

    error = size < minHeaderSize;
    BER_TLV_ASSERT_NON_FATAL(size >= minHeaderSize, "Invalid size (%d). It should be at "
                                                    "least the minimum header size (%d). Interrupting data parsing.\n",
                             size,
                             minHeaderSize);
    if (error)
        return true;

    tlvObjOut->tag = __getTag(data);
    dataP += tlvObjOut->tagSize;
    tlvObjOut->lengthSize = __getLengthFieldSize(dataP);
    tlvObjOut->lengthValue = __getLength(dataP);
    tlvObjOut->valueSize = __getValueSize(dataP);

    uint8_t fullObjSize = tlvObjOut->tagSize + tlvObjOut->lengthSize + tlvObjOut->valueSize;
    error = size < fullObjSize;
    BER_TLV_ASSERT_NON_FATAL(size >= fullObjSize, "Invalid size (%d). It should be at least %d bytes -> tag size(%d) +"
                                                  "length size(%d) + value size(%d).\n Interrupting data parsing.",
                             size,
                             fullObjSize,
                             tlvObjOut->tagSize,
                             tlvObjOut->lengthSize,
                             tlvObjOut->valueSize);
    if (error)
        return true;

    dataP += tlvObjOut->lengthSize;

    tlvObjOut->value = dataP;

    return false;
}

//-----------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------Ptivate functions------------------------------------------------------//
static uint8_t __getClassIndex(uint8_t tagByte)
{
    return ((tagByte & TAG_CLASS_MASK) >> TAG_CLASS_BIT_POS);
}

static uint8_t __getObjTypeIndex(uint8_t tagByte)
{
    return ((tagByte & TAG_OBJ_TYPE_MASk) >> TAG_OBJ_TYPE_BIT_POS);
}

static const char *__getClassString(TBerTlvObj *tlvObj)
{
    uint8_t *tagByte = (uint8_t *)&tlvObj->tag;
    tagByte += (tlvObj->tagSize - 1);
    uint8_t index = __getClassIndex(*tagByte);
    return BER_TLV_CLASSES[index];
}

static const char *__getObjTypeString(TBerTlvObj *tlvObj)
{
    uint8_t *tagByte = (uint8_t *)&tlvObj->tag;
    tagByte += (tlvObj->tagSize - 1);
    uint8_t index = __getObjTypeIndex(*tagByte);
    return BER_TLV_OBJECTS_TYPES[index];
}

static uint8_t __getTagSize(uint8_t fistTagByte)
{
    return (((fistTagByte & TWO_BYTES_TAG_MASK) == TWO_BYTES_TAG_MASK) ? 2 : 1);
}

static uint16_t __getTag(uint8_t *data)
{
    uint16_t tag = 0;
    bool twoBytesTag = ((*data & TWO_BYTES_TAG_MASK) == TWO_BYTES_TAG_MASK);
    tag = *data;
    if (twoBytesTag)
    {
        tag <<= 8;
        tag |= *(data + 1);
    }
    return tag;
}

static uint16_t __getLengthFieldSize(uint8_t *data)
{
    if (*data & MULTPLES_BYTES_LENGTH_MASK)
    {
        return (*data & (~MULTPLES_BYTES_LENGTH_MASK)) + 1;
    }
    return 1;
}

static uint16_t __getLength(uint8_t *data)
{
    uint32_t length = 0;
    uint8_t size = __getLengthFieldSize(data);
    uint8_t *dataPtr = data;
    while (size)
    {
        length <<= 8;
        length |= *dataPtr;
        ++dataPtr;
        --size;
    }

    return length;
}

static uint32_t __getValueSize(uint8_t *data)
{
    uint32_t valueSize = 0;
    uint8_t size = __getLengthFieldSize(data);
    uint8_t *dataPtr = data;

    if (size == 1)
        return *data;
    --size;
    dataPtr++;

    while (size)
    {
        valueSize |= *dataPtr;
        ++dataPtr;
        --size;
        if (size)
            valueSize <<= 8;
    }
    return valueSize;
}

static bool __isConstructed(TBerTlvObj *tlvObj)
{
    uint8_t *tagPtr = (uint8_t *)&tlvObj->tag;
    if (tlvObj->tagSize > 1)
    {
        tagPtr += (tlvObj->tagSize - 1);
    }
    return ((*tagPtr & TAG_OBJ_TYPE_MASk) >> TAG_OBJ_TYPE_BIT_POS) == 1;
}

static char *__addIndentation(char *str, uint16_t constructedLevels)
{
    uint8_t spaceCount = constructedLevels * 2;
    while (spaceCount--)
    {
        *str++ = ' ';
    }
    *str = 0;
    return str;
}
