/*
 * SlopePK 3DS port - EPK1/EPK2/EPK3 extractor with SD file picker
 * No third-party libraries: AES-128/256 ECB is built in, only libc is used.
 *
 * PS5 build (popups on, fixed paths /data/slopepk/epk.epk -> /data/slopepk/output):
 *     export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
 *     $PS5_PAYLOAD_SDK/bin/prospero-clang -O2 -std=c11 -o slopepk.elf slopepk.c -lkernel_sys
 *
 * Host build (no SDK, popups printed to stdout, optional args: <in.epk> <outdir>):
 *     cc -O2 -std=c11 -DSLOPEPK_HOST -o slopepk slopepk.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#if defined(SLOPEPK_3DS)
#include <3ds.h>
#elif !defined(SLOPEPK_PS5)
#include <nds.h>
#include <fat.h>
#endif
#include <stdarg.h>

/* ===================== EPK keys ===================== */
/* EPK collection from the supplied Unixtract source. */
typedef struct { const char *name; const unsigned char *key; size_t len; } epk_key_t;

static const unsigned char epk_key_0[] = {0x21,0x4B,0xF3,0xC1,0x29,0x54,0x7A,0xF3,0x1D,0x32,0xA5,0xEC,0xB4,0x74,0x21,0x92};
static const unsigned char epk_key_1[] = {0x1F,0x1E,0x1D,0x1C,0x1B,0x1A,0x19,0x18,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
static const unsigned char epk_key_2[] = {0x71,0x84,0xC9,0xC4,0x28,0xD0,0x3C,0x44,0x51,0x88,0x23,0x4D,0x5A,0x82,0x71,0x96};
static const unsigned char epk_key_3[] = {0x38,0x5A,0x99,0x24,0x30,0x19,0x6A,0x8C,0x44,0xF1,0x98,0x58,0x23,0xC0,0x14,0x40};
static const unsigned char epk_key_4[] = {0x8E,0x32,0xE4,0x60,0x88,0x71,0xEC,0xE9,0xB6,0x30,0x19,0x99,0xD5,0x15,0x5A,0x07};
static const unsigned char epk_key_5[] = {0x68,0x56,0xA0,0x48,0x24,0x75,0xA8,0xB4,0x17,0x28,0xA3,0x54,0x74,0x81,0x02,0x03};
static const unsigned char epk_key_6[] = {0x2F,0x2E,0x2D,0x2C,0x2B,0x2A,0x29,0x28,0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10};
static const unsigned char epk_key_7[] = {0x21,0x2D,0x3B,0x2A,0x5C,0x2D,0x3A,0x2C,0x4D,0x5B,0x23,0x4B,0x1A,0x32,0x1D,0x2A};
static const unsigned char epk_key_8[] = {0x4F,0x83,0x6A,0xAE,0xB4,0x30,0x1F,0x26,0x17,0x2A,0x9B,0x0E,0x11,0x20,0xEA,0xF4};
static const unsigned char epk_key_9[] = {0x4E,0xE6,0x62,0xC7,0xA2,0xC0,0x91,0x7F,0x73,0x28,0xDE,0x73,0xA0,0x83,0x6C,0x6B};
static const unsigned char epk_key_10[] = {0x2F,0x53,0x4A,0xBE,0x34,0x80,0x1A,0x36,0xB7,0xDA,0x6B,0x3E,0xB1,0xC0,0x4A,0xD4};
static const unsigned char epk_key_11[] = {0x7B,0x2C,0xA5,0x94,0x3D,0x2E,0x75,0x2C,0xF5,0x86,0x06,0x22,0x8C,0x5B,0x2D,0xAD};
static const unsigned char epk_key_12[] = {0x1C,0xEE,0x92,0xD0,0xFC,0x29,0x31,0xC5,0x97,0xA5,0x49,0x78,0x9F,0xCD,0x06,0xB9};
static const unsigned char epk_key_13[] = {0xD5,0x5C,0x68,0x64,0x03,0x5A,0x8C,0x8A,0x2B,0x35,0xA6,0xD6,0xC4,0x56,0x55,0x96};
static const unsigned char epk_key_14[] = {0xAD,0xB9,0x2D,0x9E,0x23,0x03,0x55,0x22,0xF4,0x70,0x8C,0xC2,0x59,0xB3,0x1E,0xA2};
static const unsigned char epk_key_15[] = {0xD2,0xE6,0xEE,0x17,0x63,0x9D,0xFE,0x2F,0x81,0xD3,0x84,0x0F,0xA0,0xBC,0x33,0x4A};
static const unsigned char epk_key_16[] = {0x4F,0x6D,0xE8,0x0C,0x03,0x62,0xFD,0x56,0x24,0x64,0xBC,0x20,0x73,0xD1,0x55,0x67};
static const unsigned char epk_key_17[] = {0x88,0x72,0x3D,0x91,0x92,0x07,0x12,0xD0,0xBA,0xFE,0x87,0xA2,0x5E,0x6E,0x8E,0xC7};
static const unsigned char epk_key_18[] = {0x68,0xA2,0x84,0xB4,0x95,0x3C,0xAD,0x15,0x02,0x4B,0xED,0x2C,0x4F,0x85,0x2A,0x09};
static const unsigned char epk_key_19[] = {0x19,0xF5,0x1E,0xE9,0xB9,0x49,0xC8,0x9E,0x41,0xAE,0x13,0x6F,0x48,0xBB,0x40,0x5C};
static const unsigned char epk_key_20[] = {0xF8,0xF6,0xBD,0x1A,0xA2,0x45,0x06,0xC2,0x75,0x9E,0x1B,0xE1,0xD5,0x1B,0xB4,0x3C};
static const unsigned char epk_key_21[] = {0x96,0xF4,0x64,0xCB,0x29,0xCD,0xFF,0x54,0x41,0xFD,0x87,0xD4,0x7D,0x08,0x4F,0xF8};
static const unsigned char epk_key_22[] = {0x6F,0xCC,0xC4,0xAA,0x33,0x89,0xB6,0x14,0xBA,0xBE,0x46,0x24,0x98,0xD2,0x02,0x0A};
static const unsigned char epk_key_23[] = {0x80,0x6B,0x98,0x22,0x79,0x52,0x18,0x09,0xDB,0xAD,0x9E,0x2E,0x6B,0xF3,0x77,0x76,0x39,0x03,0x56,0x5A,0x7E,0xB4,0x60,0x4B,0xAB,0x1E,0x15,0x03,0xDB,0xFC,0x43,0x26};
static const unsigned char epk_key_24[] = {0xB6,0x51,0x19,0xE0,0xE6,0xCB,0x5D,0xB1,0x9C,0x69,0xB4,0xCC,0x78,0xFA,0xC3,0xA8,0x7C,0x74,0x7E,0x5A,0xEF,0xDE,0x8F,0xF5,0x8F,0x2C,0xD4,0x71,0x28,0xD9,0xE1,0x6D};
static const unsigned char epk_key_25[] = {0xFC,0x9D,0x81,0xDE,0xC2,0x06,0xBA,0x62,0x61,0x4C,0x94,0x9C,0x43,0xD2,0xDA,0x91,0xD2,0x3E,0x9F,0xF3,0xDF,0x96,0x74,0xD6,0x9A,0x44,0x4D,0x13,0x27,0x7B,0xDF,0x96};
static const unsigned char epk_key_26[] = {0x34,0x35,0x66,0x33,0x31,0x31,0x37,0x32,0x31,0x65,0x38,0x38,0x30,0x63,0x66,0x35,0x38,0x30,0x61,0x61,0x64,0x31,0x31,0x65,0x33,0x35,0x32,0x33,0x34,0x61,0x30,0x34};
static const unsigned char epk_key_27[] = {0x1F,0xB2,0xC3,0xB7,0x89,0xD5,0xEA,0x48,0xED,0x16,0xE7,0x9A,0x03,0x43,0x98,0x6C,0x69,0x1D,0xAC,0xEC,0x87,0x2B,0xB0,0x77,0x87,0xD0,0xF7,0x22,0xAF,0x5D,0x1E,0x2C};
static const unsigned char epk_key_28[] = {0x48,0x13,0xB5,0xB6,0x3C,0x99,0x8A,0x28,0x74,0xEF,0x33,0x20,0x68,0x4A,0xC8,0xD9};
static const unsigned char epk_key_29[] = {0x14,0xB3,0x62,0x34,0x88,0x21,0x22,0x50,0xC7,0xC9,0x92,0xAA,0xCD,0x53,0x74,0x47};
static const unsigned char epk_key_30[] = {0x12,0xC3,0x44,0xFD,0xD2,0x87,0x1C,0x98,0x3C,0xD0,0xFB,0xBC,0x25,0x14,0x39,0x74};
static const unsigned char epk_key_31[] = {0x34,0xCC,0x21,0x9D,0x3A,0xFC,0x10,0x24,0x33,0x10,0x9B,0xBC,0x1D,0xA4,0x40,0x95};
static const unsigned char epk_key_32[] = {0x5A,0x16,0x7D,0x8C,0x34,0x2E,0xF0,0x94,0x80,0x0E,0x7C,0xFA,0x2D,0x10,0xF2,0xD0};
static const unsigned char epk_key_33[] = {0x13,0xF5,0x6B,0xE4,0xB4,0xA0,0x82,0x95,0x98,0xDB,0x8F,0x74,0x06,0x5A,0x26,0x3B};
static const unsigned char epk_key_34[] = {0x36,0x79,0xEF,0x18,0x40,0xB7,0xFD,0xEB,0xC1,0xFB,0xF9,0x5A,0x0C,0xAF,0xCE,0x3E};
static const unsigned char epk_key_35[] = {0x58,0x04,0xDF,0x78,0xCB,0x8D,0xC6,0xA7,0x1C,0x05,0xDA,0xB0,0xF1,0xED,0xE3,0xE1};
static const unsigned char epk_key_36[] = {0x1B,0x3C,0x76,0xAD,0xD3,0xF5,0xEE,0x6B,0x08,0x9D,0xB2,0x53,0x74,0x7A,0x8C,0xD4};
static const unsigned char epk_key_37[] = {0x3C,0x9D,0x30,0xDF,0x3A,0x95,0xC1,0xAA,0x41,0x92,0x88,0x13,0x29,0x2B,0xD9,0x47};
static const unsigned char epk_key_38[] = {0x89,0xE1,0x1D,0x49,0x83,0x92,0xF5,0xA5,0x21,0x14,0x57,0x38,0xEF,0x03,0x6A,0xE5};
static const unsigned char epk_key_39[] = {0x43,0x7C,0x02,0xF0,0xDF,0x99,0xF2,0x07,0x2D,0x1A,0x64,0xEE,0xBB,0xD2,0x95,0x3B};
static const unsigned char epk_key_40[] = {0x34,0x71,0xD9,0xBF,0xC5,0xF4,0xB3,0x4A,0x89,0x97,0xD5,0x69,0x32,0xF3,0x4D,0x94};
static const unsigned char epk_key_41[] = {0x3F,0xE1,0xCB,0xE1,0x1B,0xD6,0x58,0xBB,0x37,0x81,0x3E,0x05,0x05,0x2D,0x5F,0xE5};
static const unsigned char epk_key_42[] = {0xA2,0xFA,0x48,0xFC,0xC1,0xA2,0x2F,0xD2,0xF1,0x94,0x4B,0xEF,0xA8,0x40,0x37,0x65,0xEF,0x17,0x8D,0x4F,0x4A,0xB0,0xE8,0x1A,0xC7,0xB5,0xB2,0x67,0xAC,0xBD,0xF1,0x4D};
static const unsigned char epk_key_43[] = {0xE5,0x29,0xBC,0xDE,0xDF,0x8E,0x49,0x66,0x7C,0x0F,0xA3,0xA8,0x11,0x74,0xB6,0x5E};
static const unsigned char epk_key_44[] = {0x4A,0xCD,0x2C,0xA8,0x42,0x5B,0xBA,0x6C,0x49,0xFD,0x03,0xA1,0x74,0x30,0x02,0x39};
static const unsigned char epk_key_45[] = {0xC9,0xEF,0x64,0x54,0x24,0xA6,0x25,0xBB,0xAE,0x75,0x21,0x39,0x45,0x64,0x02,0x5E,0xC6,0x25,0x26,0x58,0xFB,0x65,0x0D,0x33,0x63,0x31,0x11,0xBD,0x40,0xC7,0x60,0x11};
static const unsigned char epk_key_46[] = {0x94,0x42,0x88,0x79,0x8A,0x12,0x2C,0x61,0x30,0xB6,0x61,0xBE,0xE5,0x2D,0xF4,0xFE,0x42,0x12,0x0F,0x60,0xA6,0x1E,0x31,0x2D,0xCF,0xC1,0x41,0x1E,0x30,0x0A,0x29,0xAE};
static const unsigned char epk_key_47[] = {0x38,0x61,0x33,0x32,0x37,0x63,0x32,0x38,0x61,0x31,0x36,0x63,0x34,0x38,0x66,0x32,0x39,0x62,0x32,0x38,0x62,0x30,0x37,0x65,0x63,0x35,0x62,0x34,0x33,0x35,0x38,0x62};
static const unsigned char epk_key_48[] = {0xCF,0x5D,0x6D,0xC9,0x34,0xF1,0x86,0x18,0xB9,0x68,0x38,0x23,0x68,0xE1,0x7B,0xA9,0x71,0xDE,0xAA,0x2E,0xCD,0xFC,0x90,0x68,0x74,0xB3,0x27,0xD8,0x70,0x76,0xE2,0x28};
static const unsigned char epk_key_49[] = {0x53,0xD6,0xDC,0x79,0x41,0x8C,0x1A,0x23,0x71,0xDC,0x9F,0x92,0x6C,0xD3,0xA3,0xA0,0x6F,0x4E,0x7E,0x43,0x96,0x46,0x4B,0x5F,0x41,0x24,0x80,0x83,0xC2,0xC6,0x56,0x37};
static const unsigned char epk_key_50[] = {0xB7,0x72,0x4D,0xBB,0xF2,0xAE,0xA0,0x73,0x13,0x1E,0x8E,0x7D,0x62,0xD1,0x14,0xE2,0xAA,0x02,0xF9,0x9D,0x17,0xCD,0x73,0x50,0xC1,0x44,0x66,0x62,0x45,0x28,0xED,0x79};
static const unsigned char epk_key_51[] = {0xFE,0x90,0xB0,0xC1,0xBE,0x8C,0xC2,0x8A,0x97,0x38,0x33,0x3F,0x95,0xAC,0x2C,0x58,0x77,0x7B,0xDE,0x7D,0x4E,0x8C,0xAB,0xAB,0xA7,0x3B,0x24,0xFB,0x7D,0x17,0x81,0xC7};
static const unsigned char epk_key_52[] = {0x52,0xA2,0x08,0xFA,0x24,0xE7,0xE7,0x07,0x30,0xA4,0x09,0x99,0xB1,0xC2,0x2C,0x14,0x8F,0x49,0x20,0x48,0x4B,0xC5,0x0B,0x51,0x5D,0x24,0x3E,0x35,0xD1,0x46,0x89,0xF1};
static const unsigned char epk_key_53[] = {0x69,0xBC,0x99,0x1D,0xF6,0x69,0x9C,0x78,0xD6,0x4F,0x9D,0x37,0x97,0x35,0x24,0x8A,0x94,0x09,0xF3,0x49,0x35,0x50,0x11,0xD5,0x6D,0xAF,0xDD,0x78,0x38,0x00,0xBE,0xBF};
static const unsigned char epk_key_54[] = {0xCD,0x41,0x71,0xFC,0x9C,0x06,0x86,0x96,0x27,0xA6,0x7E,0xA7,0xB6,0x6D,0x73,0x9D};
static const unsigned char epk_key_55[] = {0x0E,0xE5,0x2A,0x12,0xA2,0xEB,0x5D,0xE2,0xE1,0x39,0x99,0x18,0x7B,0x14,0x91,0x3F,0x6D,0x33,0x67,0xA7,0x9B,0x39,0xAC,0x35,0x97,0x9A,0x51,0xE5,0xC1,0x2A,0x4F,0xDF};
static const unsigned char epk_key_56[] = {0xE2,0x7E,0x6A,0xFE,0x44,0xB7,0x86,0x6D,0x60,0xC2,0x4E,0xD2,0x79,0x04,0xEC,0xB2,0x96,0xCA,0x69,0xB4,0x25,0x14,0x78,0xB5,0x24,0x8C,0x03,0x85,0x1F,0x08,0xEC,0xF5};
static const unsigned char epk_key_57[] = {0xF2,0xB7,0x8A,0xEB,0xAD,0x6D,0x86,0xA1,0x7B,0x47,0x42,0xB2,0xB8,0x4B,0x60,0xF4};
static const unsigned char epk_key_58[] = {0xC2,0xFB,0xBC,0x5D,0xDD,0x9D,0x36,0x6B,0x7F,0xD6,0xCA,0xEB,0x90,0xF8,0x60,0x39};
static const unsigned char epk_key_59[] = {0x1C,0x96,0x6D,0xFA,0x0E,0x5A,0xE9,0x94,0x6A,0xAF,0x8D,0x2E,0xC0,0x6B,0x9E,0x18};
static const unsigned char epk_key_60[] = {0xAD,0x17,0xA5,0x92,0x3B,0x52,0x5F,0xD2,0x1D,0xB7,0x65,0xA5,0xB6,0x82,0x2F,0xBD};
static const unsigned char epk_key_61[] = {0x38,0x8B,0xE4,0xB0,0x4B,0xD9,0x8E,0x7C,0x3C,0xA4,0x5A,0x4C,0x6C,0xA3,0x46,0xDD,0x2E,0xB3,0x2B,0xDC,0xD0,0x5D,0xC2,0x8F,0xC4,0xA8,0x7C,0x96,0x25,0x29,0x4A,0x5E};
static const unsigned char epk_key_62[] = {0x37,0x70,0x50,0xF9,0xB9,0xD9,0x1C,0xD8,0x03,0xAC,0xAA,0xCC,0xEA,0x40,0x46,0xDD,0x99,0xB0,0x1C,0xFB,0xB0,0x01,0x04,0x51,0xF4,0xF8,0x7A,0x16,0x20,0xC4,0xBA,0xEF};
static const unsigned char epk_key_63[] = {0x39,0x53,0x24,0xAD,0x36,0x9A,0x52,0x9E,0xAB,0xAC,0x71,0xFE,0x1E,0x72,0xC2,0x5C,0xE2,0x55,0x94,0x29,0x4D,0x47,0x30,0x3B,0xCB,0x26,0x29,0x24,0x1A,0xFA,0x4C,0x98};
static const unsigned char epk_key_64[] = {0x74,0x51,0x46,0x76,0xD6,0x8B,0x9A,0x72,0xA0,0x09,0x3C,0xEF,0x56,0xD3,0x06,0x74,0x84,0xE1,0xF4,0xD5,0xCF,0x7D,0x4B,0x4E,0xD3,0x89,0xBE,0xD0,0x30,0xFA,0x1B,0x09};
static const unsigned char epk_key_65[] = {0x6A,0x42,0xD2,0x48,0x5B,0x71,0x6B,0x25,0xAE,0x5C,0x99,0x21,0x17,0x65,0x88,0xD1,0x67,0xC2,0x5B,0x90,0x2D,0x4E,0xF2,0x90,0x3A,0xF5,0xC1,0xFC,0xC6,0x1D,0x34,0xC9};
static const unsigned char epk_key_66[] = {0xA3,0x5A,0x57,0xDF,0xDD,0x82,0x66,0xF7,0xCE,0x1A,0xF9,0x91,0xEC,0x67,0xBA,0xBF,0x67,0x23,0x65,0x3A,0xBB,0x9A,0x7D,0x48,0xA4,0xB8,0xAB,0x2A,0x24,0x85,0xBC,0xFE};
static const unsigned char epk_key_67[] = {0x70,0x33,0x73,0x36,0x76,0x38,0x79,0x2F,0x42,0x3F,0x45,0x28,0x48,0x2B,0x4D,0x62,0x51,0x65,0x54,0x68,0x57,0x6D,0x5A,0x71,0x34,0x74,0x37,0x77,0x21,0x7A,0x24,0x43};
static const unsigned char epk_key_68[] = {0x62,0x51,0x65,0x54,0x68,0x57,0x6D,0x5A,0x71,0x33,0x74,0x36,0x77,0x39,0x7A,0x24,0x43,0x26,0x46,0x29,0x4A,0x40,0x4E,0x63,0x52,0x66,0x55,0x6A,0x58,0x6E,0x32,0x72};
static const unsigned char epk_key_69[] = {0x37,0x64,0x33,0x63,0x61,0x63,0x34,0x37,0x32,0x61,0x66,0x37,0x36,0x39,0x38,0x36,0x63,0x35,0x38,0x63,0x36,0x30,0x39,0x31,0x63,0x32,0x38,0x30,0x31,0x62,0x66,0x37};
static const unsigned char epk_key_70[] = {0x64,0xE6,0x29,0xFD,0xD8,0xB7,0xBE,0x4A,0x3D,0x4E,0xCD,0x85,0xF1,0xBF,0xCE,0x6F,0xC4,0x9C,0xDE,0xF3,0x2C,0xFF,0xB1,0x6B,0x47,0x16,0xA7,0xBE,0xE6,0xF3,0xB2,0x58};
static const unsigned char epk_key_71[] = {0xDF,0xFD,0x1E,0x4F,0x09,0x3E,0x30,0x54,0x51,0xD4,0xF3,0x75,0x2E,0x63,0xBA,0x9A,0x3E,0x6A,0x64,0x04,0x92,0x2D,0x98,0x6D,0xF3,0x6C,0x00,0x81,0x8F,0x55,0x95,0xC1};
static const unsigned char epk_key_72[] = {0xEC,0x2C,0x89,0xB4,0xAF,0x45,0xB5,0xEB,0x7E,0xA9,0xA8,0x3D,0xD2,0x38,0x78,0x10,0xC0,0x81,0x5B,0xD3,0x1B,0xBF,0xE1,0xD1,0x7C,0x80,0x9E,0x7D,0x68,0x33,0x91,0x12};
static const unsigned char epk_key_73[] = {0x90,0xA2,0x1E,0x96,0xD3,0x9A,0x93,0x39,0x82,0xB7,0x50,0x8E,0x59,0x27,0x20,0x40,0xDC,0xA3,0x4E,0xB4,0x78,0x2F,0xF2,0x89,0xD1,0xAF,0xEF,0xEC,0x0C,0x68,0x59,0x0C};
static const unsigned char epk_key_74[] = {0xF3,0x22,0xA9,0xCA,0x1D,0x52,0x3C,0x35,0x8D,0xD2,0xFD,0x97,0xD5,0x66,0x0E,0x25,0x38,0x6C,0x9C,0x60,0xE4,0x23,0x63,0x2A,0xEC,0x97,0x23,0xD2,0x82,0xBE,0x97,0x1D};
static const unsigned char epk_key_75[] = {0x62,0x52,0xA0,0x81,0x68,0x84,0x99,0x7B,0x2F,0xCA,0x30,0x66,0x25,0x61,0xA7,0x21,0xA4,0xBC,0xC4,0x0B,0x18,0xCB,0xEA,0x5D,0x36,0x3F,0xA8,0x44,0xF1,0x7D,0x7D,0xE9};
static const unsigned char epk_key_76[] = {0x69,0x25,0xE5,0x66,0x90,0xA2,0x1F,0x89,0x0F,0x00,0x63,0xA1,0x86,0x11,0xBC,0xFF,0x0D,0x78,0x6C,0xA5,0x54,0xAF,0x5A,0xE5,0x9E,0x5D,0x16,0xBE,0xDC,0xD4,0x67,0xE2};
static const unsigned char epk_key_77[] = {0x76,0x38,0x79,0x2F,0x42,0x3F,0x45,0x28,0x48,0x2B,0x4D,0x62,0x51,0x65,0x53,0x68,0x56,0x6D,0x59,0x71,0x33,0x74,0x36,0x77,0x39,0x7A,0x24,0x43,0x26,0x46,0x29,0x4A};
static const unsigned char epk_key_78[] = {0x6B,0x5A,0xD1,0xBE,0x81,0xD7,0xA1,0xA4,0x94,0xF5,0x8E,0xB6,0x59,0x43,0x18,0x50,0xC1,0xB6,0x81,0x82,0x6E,0xE4,0x42,0x83,0x94,0xD4,0x89,0x70,0x52,0x69,0x17,0x56};
static const unsigned char epk_key_79[] = {0xFA,0x9E,0xBB,0x83,0x8B,0x7B,0xAF,0xBA,0x75,0xEF,0xE8,0xD5,0xA3,0x56,0x03,0x74,0xEB,0x06,0x99,0xA1,0x13,0x41,0x1C,0xA9,0x24,0x05,0x1B,0x4A,0xDB,0x52,0xE1,0x0D};
static const unsigned char epk_key_80[] = {0x1A,0x8A,0xDA,0xB2,0x1D,0x9F,0xF9,0x95,0x67,0x7D,0xB3,0x2B,0xCE,0x2E,0x0C,0xD5,0x59,0xAE,0x86,0x84,0x0E,0xBF,0x4A,0x69,0x68,0x72,0x07,0x6E,0x37,0xDF,0xFE,0x8F};
static const unsigned char epk_key_81[] = {0x25,0xDF,0x24,0x16,0x67,0x45,0xB5,0x2E,0xAB,0x66,0x14,0x55,0xBE,0xD4,0x3D,0xE3,0x76,0x32,0x0F,0xAA,0x1F,0x78,0x24,0x87,0x7B,0x93,0x8D,0xB8,0x69,0x30,0x8B,0x18};
static const unsigned char epk_key_82[] = {0xB2,0xE8,0xC3,0xE2,0x14,0xF0,0x44,0xB8,0x23,0x91,0x6E,0x48,0xFA,0x07,0x4E,0x60,0x6C,0x7C,0x5C,0xD5,0xE6,0x90,0x2B,0x6F,0x99,0xBD,0x90,0x3D,0xAC,0x0C,0x79,0x2F};
static const unsigned char epk_key_83[] = {0x9F,0x13,0x9A,0x93,0xEA,0x34,0x05,0xC3,0x2E,0xD6,0xC3,0x69,0x97,0x42,0xC5,0x8A,0xA5,0xF1,0xE5,0x13,0x3A,0x7D,0xEA,0x48,0x5A,0x5F,0xA2,0x1A,0x76,0xA3,0xB7,0x71};
static const unsigned char epk_key_84[] = {0xB2,0x39,0x81,0xFD,0x36,0x42,0xCD,0xF4,0x01,0xE7,0xA0,0xC2,0xFA,0xDB,0xDA,0x43,0x99,0xB6,0xAA,0xF9,0x60,0x0B,0x80,0x21,0x44,0x93,0x3B,0x4F,0x4E,0x58,0x55,0xEA};
static const unsigned char epk_key_85[] = {0x19,0x78,0xA9,0xFD,0x71,0x37,0xF4,0x40,0x13,0xFF,0xE1,0x16,0xBB,0xC3,0x4E,0x91,0xD1,0x1C,0xEF,0x52,0xAE,0x21,0x77,0x68,0x44,0xE7,0xC2,0x81,0x99,0x51,0x34,0x63};
static const unsigned char epk_key_86[] = {0x32,0x63,0x65,0x37,0x64,0x62,0x39,0x32,0x37,0x62,0x35,0x32,0x36,0x37,0x65,0x36,0x37,0x63,0x30,0x35,0x36,0x30,0x66,0x35,0x38,0x33,0x30,0x32,0x35,0x38,0x34,0x66};
static const unsigned char epk_key_87[] = {0x46,0x71,0x5D,0xFB,0xDE,0x23,0xC2,0xD8,0xCB,0xA7,0xEC,0x4F,0x36,0xBA,0x41,0xAA,0xD2,0x8E,0x7E,0xC0,0x0F,0xEC,0x51,0xF2,0x84,0x3F,0x24,0x65,0x4D,0xB0,0x9B,0xD3};
static const unsigned char epk_key_88[] = {0x62,0x38,0x32,0x33,0x34,0x66,0x32,0x32,0x39,0x66,0x32,0x61,0x37,0x62,0x31,0x65,0x37,0x33,0x37,0x31,0x33,0x38,0x32,0x30,0x66,0x64,0x66,0x61,0x36,0x33,0x35,0x64};
static const unsigned char epk_key_89[] = {0x9E,0x8D,0x2B,0xAC,0x9D,0xCB,0xEF,0xC8,0x78,0xCC,0x82,0x03,0x43,0x1A,0x70,0xE0,0x0C,0x21,0x22,0xDE,0xF8,0x2F,0xD5,0x09,0x9D,0x04,0xBA,0x25,0x9B,0x1B,0x2E,0x4B};

static const epk_key_t EPK_KEYS[] = {
    {"unknown", epk_key_0, sizeof(epk_key_0)},
    {"BCM35230/early MTK5369 and LG1152", epk_key_1, sizeof(epk_key_1)},
    {"mtk5369 - Mediatek GP4", epk_key_2, sizeof(epk_key_2)},
    {"mtk5398 (a2) - Mediatek NetCast 4/4.5", epk_key_3, sizeof(epk_key_3)},
    {"mtka5lr (mt5882) - Mediatek webOS 2 (2015)", epk_key_4, sizeof(epk_key_4)},
    {"new BCM35230", epk_key_5, sizeof(epk_key_5)},
    {"Saturn7/BCM3556", epk_key_6, sizeof(epk_key_6)},
    {"new Saturn7/old LM1", epk_key_7, sizeof(epk_key_7)},
    {"LM1 PDP", epk_key_8, sizeof(epk_key_8)},
    {"LM1 LCD", epk_key_9, sizeof(epk_key_9)},
    {"m1 - MStar non-webOS", epk_key_10, sizeof(epk_key_10)},
    {"m1a - MStar non-webOS (L15 signage)", epk_key_11, sizeof(epk_key_11)},
    {"m1ap - MStar L16", epk_key_12, sizeof(epk_key_12)},
    {"m2 - MStar SimpleSmart", epk_key_13, sizeof(epk_key_13)},
    {"m2 - MStar webOS 3.0 (2016)", epk_key_14, sizeof(epk_key_14)},
    {"m2r - MStar webOS 3.5 (2017)", epk_key_15, sizeof(epk_key_15)},
    {"m3 - MStar webOS 4.0 (2018)", epk_key_16, sizeof(epk_key_16)},
    {"m3r - MStar webOS 4.5 (2019)", epk_key_17, sizeof(epk_key_17)},
    {"lm14 - MStar NetCast 4.5 (2014/2015)", epk_key_18, sizeof(epk_key_18)},
    {"lm14a - MStar webOS 2 (2015)", epk_key_19, sizeof(epk_key_19)},
    {"lm14alite - MStar webOS 2 (2015)", epk_key_20, sizeof(epk_key_20)},
    {"lm15u - MStar webOS 2 (2015)", epk_key_21, sizeof(epk_key_21)},
    {"lm18a - MStar webOS 4.0 (2018)", epk_key_22, sizeof(epk_key_22)},
    {"lm21a - MStar webOS 6 (2021)", epk_key_23, sizeof(epk_key_23)},
    {"lm21u (mt5889) - MStar webOS 6 (2021)", epk_key_24, sizeof(epk_key_24)},
    {"lm21ut - MStar webOS 6 StanbyME (2022)", epk_key_25, sizeof(epk_key_25)},
    {"lm21an - MStar webOS 7 (2022)", epk_key_26, sizeof(epk_key_26)},
    {"lm21ann - MStar webOS 8 (2023)", epk_key_27, sizeof(epk_key_27)},
    {"lg1152 - LX GP4", epk_key_28, sizeof(epk_key_28)},
    {"lg115x - LX NC4", epk_key_29, sizeof(epk_key_29)},
    {"lg1154 (h13, goldfinger) - LX webOS 1 (2014)", epk_key_30, sizeof(epk_key_30)},
    {"m14 (m14tv) - LX webOS 1 (2014)", epk_key_31, sizeof(epk_key_31)},
    {"m14 (m14tv) - LX webOS 2 (2015)", epk_key_32, sizeof(epk_key_32)},
    {"h15 - LX webOS 2 (2015)", epk_key_33, sizeof(epk_key_33)},
    {"m16 - LX webOS 3.0 (2016)", epk_key_34, sizeof(epk_key_34)},
    {"m16lite - LX webOS 3.0 (2016)", epk_key_35, sizeof(epk_key_35)},
    {"m16p - LX webOS 3.5 (2017)", epk_key_36, sizeof(epk_key_36)},
    {"m16plite - LX webOS 3.5 (2017)", epk_key_37, sizeof(epk_key_37)},
    {"m16pstb - LX webOS 3.5 (2017)", epk_key_38, sizeof(epk_key_38)},
    {"m16pp - LX webOS 4.0 (2018)", epk_key_39, sizeof(epk_key_39)},
    {"m16pplite - LX webOS 4.0 (2018)", epk_key_40, sizeof(epk_key_40)},
    {"m16p3 - LX webOS 4.5 (2019)", epk_key_41, sizeof(epk_key_41)},
    {"m23 - LX webOS 8 (2023)", epk_key_42, sizeof(epk_key_42)},
    {"o18 - LX webOS 4.0 (2018)", epk_key_43, sizeof(epk_key_43)},
    {"o18 - LX webOS 4.5 (2019)", epk_key_44, sizeof(epk_key_44)},
    {"o20 - LX webOS 5 (2020)", epk_key_45, sizeof(epk_key_45)},
    {"o20n - LX webOS 6 (2021)", epk_key_46, sizeof(epk_key_46)},
    {"o22 - LX webOS 7 (2022)", epk_key_47, sizeof(epk_key_47)},
    {"o22n - LX webOS 8 (2023)", epk_key_48, sizeof(epk_key_48)},
    {"o22n2 - LX webOS 9 (2024)", epk_key_49, sizeof(epk_key_49)},
    {"o24 - LX webOS 9 (2024)", epk_key_50, sizeof(epk_key_50)},
    {"o22n3 - LX webOS 10 (2025)", epk_key_51, sizeof(epk_key_51)},
    {"o24n - LX webOS 10 (2025)", epk_key_52, sizeof(epk_key_52)},
    {"o26 - LX webOS 11 (2026)", epk_key_53, sizeof(epk_key_53)},
    {"o18k - LX webOS 4.5 (2019)", epk_key_54, sizeof(epk_key_54)},
    {"o208k - LX webOS 5 (2020)", epk_key_55, sizeof(epk_key_55)},
    {"e60n - LX webOS 6 (2021)", epk_key_56, sizeof(epk_key_56)},
    {"k2l - Realtek webOS 3.0 (2016)", epk_key_57, sizeof(epk_key_57)},
    {"k2lp - Realtek webOS 3.0 (2016)", epk_key_58, sizeof(epk_key_58)},
    {"k3lp - Realtek WebOS 3.5 (2017)", epk_key_59, sizeof(epk_key_59)},
    {"k5lp - Realtek webOS 4.5 (2019)", epk_key_60, sizeof(epk_key_60)},
    {"k6lp - Realtek webOS 5 (2020)", epk_key_61, sizeof(epk_key_61)},
    {"k6lpfhd - Realtek webOS 5 (2020)", epk_key_62, sizeof(epk_key_62)},
    {"k6hp - Realtek webOS 5 (2020)", epk_key_63, sizeof(epk_key_63)},
    {"k7lp - Realtek webOS 6 (2021)", epk_key_64, sizeof(epk_key_64)},
    {"k8lp - Realtek webOS 7 (2022)", epk_key_65, sizeof(epk_key_65)},
    {"k8hp - Realtek webOS 7 (2022)", epk_key_66, sizeof(epk_key_66)},
    {"k8lp - Realtek webOS 7 hospitality (2022)", epk_key_67, sizeof(epk_key_67)},
    {"k8hp - Realtek webOS 7 hospitality (2022)", epk_key_68, sizeof(epk_key_68)},
    {"k8ap - Realtek webOS 7 (2022)", epk_key_69, sizeof(epk_key_69)},
    {"k8hpt - Realtek webOS 7 StanbyME Go (2023)", epk_key_70, sizeof(epk_key_70)},
    {"k8hpp - Realtek webOS 8 (2023)", epk_key_71, sizeof(epk_key_71)},
    {"k8lpn - Realtek webOS 8 (2023)", epk_key_72, sizeof(epk_key_72)},
    {"kf23f - Realtek webOS 8 (2023)", epk_key_73, sizeof(epk_key_73)},
    {"kf23f - Realtek webOS 8 smart monitors (2023)", epk_key_74, sizeof(epk_key_74)},
    {"kid23q - Realtek webOS 8 ultrawide monitors (2023)", epk_key_75, sizeof(epk_key_75)},
    {"kid24u - Realtek webOS 9 UltraGear monitors (2024)", epk_key_76, sizeof(epk_key_76)},
    {"k8lpn - Realtek webOS 8 hospitality (2023)", epk_key_77, sizeof(epk_key_77)},
    {"k8lpn2 - Realtek webOS 9 (2024)", epk_key_78, sizeof(epk_key_78)},
    {"k24 - Realtek webOS 9 (2024)", epk_key_79, sizeof(epk_key_79)},
    {"k24t - Realtek webOS 9 StanbyME 2 (2024)", epk_key_80, sizeof(epk_key_80)},
    {"k25lp - Realtek webOS 10 (2025)", epk_key_81, sizeof(epk_key_81)},
    {"k24n - Realtek webOS 10 (2025)", epk_key_82, sizeof(epk_key_82)},
    {"k26 - Realtek webOS 11 (2026)", epk_key_83, sizeof(epk_key_83)},
    {"k6lpwee - Realtek webOS 5 (2020)", epk_key_84, sizeof(epk_key_84)},
    {"k6lpweefhd - Realtek webOS 5 (2020)", epk_key_85, sizeof(epk_key_85)},
    {"k8lpwee - Realtek webOS 7 (2022)", epk_key_86, sizeof(epk_key_86)},
    {"k8hpwee - Realtek webOS 7 (2022)", epk_key_87, sizeof(epk_key_87)},
    {"k8apwee - Realtek webOS 7 (2022)", epk_key_88, sizeof(epk_key_88)},
    {"kf23fwee - Realtek webOS 8 (2023)", epk_key_89, sizeof(epk_key_89)},
};
#define EPK_KEY_COUNT (sizeof(EPK_KEYS)/sizeof(EPK_KEYS[0]))

/* ===================== AES (ECB decrypt) ===================== */

#define Nb 4
#define Nk128 4
#define Nk256 8
#define Nr128 10
#define Nr256 14
static const uint8_t sbox[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const uint8_t rsbox[256]={
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};
static uint8_t xt(uint8_t x){return (uint8_t)((x<<1)^((x&0x80)?0x1b:0));}
static uint8_t mul(uint8_t a,uint8_t b){uint8_t r=0;while(b){if(b&1)r^=a;a=xt(a);b>>=1;}return r;}
/* Precompute the four finite-field multipliers used by AES InvMixColumns.
   This replaces many bitwise GF(2^8) loops per block with table lookups. */
static uint8_t mul9_table[256], mul11_table[256], mul13_table[256], mul14_table[256];
static int aes_tables_ready;
static void aes_init_tables(void){
    if(aes_tables_ready) return;
    for(unsigned i=0;i<256;i++){
        mul9_table[i]=mul((uint8_t)i,9);
        mul11_table[i]=mul((uint8_t)i,11);
        mul13_table[i]=mul((uint8_t)i,13);
        mul14_table[i]=mul((uint8_t)i,14);
    }
    aes_tables_ready=1;
}
static void add(uint8_t*s,const uint8_t*r){for(int i=0;i<16;i++)s[i]^=r[i];}
static void inv_shift(uint8_t*s){uint8_t t[16];memcpy(t,s,16);for(int r=0;r<4;r++)for(int c=0;c<4;c++)s[4*c+r]=t[4*((c-r+4)%4)+r];}
static void inv_sub(uint8_t*s){for(int i=0;i<16;i++)s[i]=rsbox[s[i]];}
static void inv_mix(uint8_t*s){
    for(int c=0;c<4;c++){
        uint8_t*a=&s[c*4];uint8_t x=a[0],y=a[1],z=a[2],w=a[3];
        a[0]=mul14_table[x]^mul11_table[y]^mul13_table[z]^mul9_table[w];
        a[1]=mul9_table[x]^mul14_table[y]^mul11_table[z]^mul13_table[w];
        a[2]=mul13_table[x]^mul9_table[y]^mul14_table[z]^mul11_table[w];
        a[3]=mul11_table[x]^mul13_table[y]^mul9_table[z]^mul14_table[w];
    }
}
static void inv_round(uint8_t*s,const uint8_t*r){inv_shift(s);inv_sub(s);add(s,r);inv_mix(s);}
static uint32_t subword(uint32_t x){return ((uint32_t)sbox[x>>24]<<24)|((uint32_t)sbox[(x>>16)&255]<<16)|((uint32_t)sbox[(x>>8)&255]<<8)|sbox[x&255];}
static uint32_t rotword(uint32_t x){return (x<<8)|(x>>24);}
static void expand(const uint8_t*k,int kl,uint8_t*rk){
    int nk=kl/4,nr=(nk==4)?10:14,nw=4*(nr+1);
    uint32_t w[60];
    for(int i=0;i<nk;i++)w[i]=((uint32_t)k[4*i]<<24)|((uint32_t)k[4*i+1]<<16)|((uint32_t)k[4*i+2]<<8)|k[4*i+3];
    uint8_t rc=1;
    for(int i=nk;i<nw;i++){
        uint32_t t=w[i-1];
        if(i%nk==0){t=subword(rotword(t))^((uint32_t)rc<<24);rc=xt(rc);}
        else if(nk==8&&i%nk==4)t=subword(t);
        w[i]=w[i-nk]^t;
    }
    /* serialize as bytes so the layout is endian-independent and alignment-safe */
    for(int i=0;i<nw;i++){rk[4*i]=(uint8_t)(w[i]>>24);rk[4*i+1]=(uint8_t)(w[i]>>16);rk[4*i+2]=(uint8_t)(w[i]>>8);rk[4*i+3]=(uint8_t)w[i];}
}
static void decblock(uint8_t*s,const uint8_t*rk,int nr){add(s,rk+16*nr);for(int r=nr-1;r>0;r--)inv_round(s,rk+16*r);inv_shift(s);inv_sub(s);add(s,rk);}
static int aes_ecb_decrypt_inplace(uint8_t*b,size_t n,const uint8_t*k,size_t kl){if((kl!=16&&kl!=32)||(!b&&n)||!k)return -1;aes_init_tables();uint8_t rk[240];int nr=(kl==16)?10:14;expand(k,(int)kl,rk);size_t full=n&~(size_t)15;for(size_t i=0;i<full;i+=16)decblock(b+i,rk,nr);return 0;}

/* ===================== EPK extractor ===================== */

static FILE *sd_log_file = NULL;
static void popup(const char *fmt, ...);
static void errp(const char *fmt, ...);
static void perr(const char *what);
static void draw_stream_progress(const char *pak, uint32_t seg, uint32_t seg_total, uint64_t done, uint64_t total);
static void log_progress_bottom(const char *message);
/* throttled progress: popup at ~10% steps, first and last item */
static void progress(const char *what,const char *name,uint32_t i,uint32_t total){
    uint32_t step=total/10; if(step<1)step=1;
    if(i==0||i+1==total||((i+1)%step)==0) popup("%s %s: segment %u/%u (%u%%)",what,name,i+1,total,(unsigned)(((uint64_t)(i+1)*100)/total));
}
#define SIG 128u
#define EPK2_HDR 1584u
#define EPK3_HDR 1712u

static uint32_t rd32le(const unsigned char *p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint32_t rd32be(const unsigned char *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static int read_at(FILE *f, uint64_t off, void *buf, size_t n){
    if (off > 0x7fffffffULL || fseek(f,(long)off,SEEK_SET)!=0) return -1;
    return fread(buf,1,n,f)==n?0:-1;
}
static unsigned char *read_alloc(FILE *f,uint64_t off,size_t n){
    unsigned char *p=malloc(n);
    if(!p){errp("Out of memory reading %u bytes at offset %llu",(unsigned)n,(unsigned long long)off);return NULL;}
    if(read_at(f,off,p,n)){errp("Short read: wanted %u bytes at offset %llu",(unsigned)n,(unsigned long long)off);free(p);return NULL;}
    return p;
}
static void trimstr(const unsigned char *p,size_t n,char *out,size_t cap){ size_t i=0; while(i<n && i+1<cap && p[i]){ unsigned char c=p[i++]; out[i-1]=(c>=32&&c<127)?(char)c:'.'; } out[i]=0; }
static int mkdir_p(const char *p){ if(mkdir(p,0777)==0 || errno==EEXIST)return 0; return -1; }
static void safe_name(char *s){ for(;*s;s++) if(!(isalnum((unsigned char)*s)||*s=='.'||*s=='_'||*s=='-'||*s=='@')) *s='_'; }

static unsigned char *aes_ecb_dec(const unsigned char *in,size_t n,const unsigned char *key,size_t klen){
    if(klen!=16 && klen!=32) return NULL;
    unsigned char *out=(unsigned char*)malloc(n); if(!out) return NULL;
    memcpy(out,in,n); if(aes_ecb_decrypt_inplace(out,n,key,klen)!=0){free(out);return NULL;}
    return out;
}
static const epk_key_t *find_key(const unsigned char *data,size_t n,const char *magic){
    for(size_t i=0;i<EPK_KEY_COUNT;i++){ unsigned char *d=aes_ecb_dec(data,n,EPK_KEYS[i].key,EPK_KEYS[i].len); if(d){ size_t ml=strlen(magic); if(n>=ml&&!memcmp(d,magic,ml)){free(d);return &EPK_KEYS[i];} free(d);} }
    return NULL;
}
static int write_file(const char *path,const unsigned char *p,size_t n){ FILE *o=fopen(path,"wb"); if(!o){perr(path);return -1;} int ok=(fwrite(p,1,n,o)==n); fclose(o); return ok?0:-1; }
static int copy_name(const unsigned char *p,size_t n,char *out,size_t cap){ trimstr(p,n,out,cap); safe_name(out); return out[0]?0:-1; }

static int is_epk1(FILE *f){ unsigned char a[4],b[4]; return read_at(f,0,a,4)==0&&read_at(f,12,b,4)==0&&!memcmp(a,"epak",4)&&memcmp(b,"EPK2",4); }
static int is_epk2(FILE *f){
    unsigned char a[16]; if(read_at(f,128,a,16)) return 0;
    if(!memcmp(a,"epak",4)) return 1;                 /* plain header */
    return find_key(a,16,"epak")!=NULL;                /* encrypted header: try built-in keys on first block */
}
static int pattern_epk3(const unsigned char *d,size_t n){ (void)n; const char *pats[]={"____X.X.X___________X.X.X___________","____X.XX.X__________X.XX.X__________","____XX.X.X__________XX.X.X__________"}; for(int k=0;k<3;k++){int ok=1;for(size_t i=0;i<36;i++){unsigned char b=d[i]; char p=pats[k][i]; if(p=='_'?b!=0:p=='X'?!isdigit(b):p=='.'?b!='.':0){ok=0;break;}}if(ok)return 1;}return 0;}
static int is_epk3(FILE *f){ unsigned char d[36]; return read_at(f,1712,d,36)==0&&pattern_epk3(d,36); }

static int extract_epk1(FILE *f,const char *outdir){
    unsigned char h[48]; if(read_at(f,0,h,48)){errp("EPK1: cannot read header");return -1;} uint32_t cntle=rd32le(h+8); int be;
    if(cntle>256)be=1; else if(cntle<33)be=0; else {errp("Unknown EPK1 variant\n");return -1;}
    uint32_t fsize=be?rd32be(h+4):rd32le(h+4), count=be?rd32be(h+8):rd32le(h+8);
    uint32_t hsize=0,max=10; if(!be){ unsigned char x[4]; if(read_at(f,12,x,4))return -1; hsize=rd32le(x); if(hsize<48||(hsize-48)/8>128){errp("Bad EPK1 header size\n");return -1;} max=(hsize-48)/8; }
    typedef struct {uint32_t off,size;} P; P *p=calloc(max,sizeof(P)); if(!p){errp("EPK1: out of memory for pak table");return -1;} size_t pc=0;
    for(uint32_t i=0;i<max;i++){unsigned char x[8];uint64_t off=be?48+i*8:48+i*8;if(read_at(f,off,x,8))break;uint32_t a=be?rd32be(x):rd32le(x),s=be?rd32be(x+4):rd32le(x+4);if(a||s){p[pc++] = (P){a,s};}}
    if(pc!=count){errp("EPK1 pak count mismatch: header=%u entries=%zu\n",count,pc);free(p);return -1;} if(mkdir_p(outdir)){perr("Create output folder");free(p);return -1;}
    printf("EPK1 %s-endian: data size=%lu, pak count=%lu\n",be?"big":"little",(unsigned long)fsize,(unsigned long)count);popup("EPK1 %s-endian: %lu paks, %lu bytes",be?"big":"little",(unsigned long)count,(unsigned long)fsize);
    for(size_t i=0;i<pc;i++){unsigned char ph[128];if(read_at(f,p[i].off,ph,128)){errp("EPK1: cannot read pak header %zu",i);free(p);return -1;}uint32_t sz=be?rd32be(ph+4):rd32le(ph+4);char name[16],plat[80];copy_name(ph,4,name,sizeof(name));trimstr(ph+8,64,plat,sizeof(plat));uint32_t want=sz;unsigned char *d=read_alloc(f,p[i].off+128,want);if(!d){errp("EPK1: cannot read pak data %s",name);free(p);return -1;}char path[4096];snprintf(path,sizeof(path),"%s/%s.bin",outdir,name);printf("(%zu/%zu) %s Offset:%lu Size:%lu Platform:%s\n",i+1,pc,name,(unsigned long)p[i].off,(unsigned long)sz,plat);popup("Pak %zu/%zu: %s (%lu bytes) plat:%s",i+1,pc,name,(unsigned long)sz,plat);if(write_file(path,d,want)){free(d);free(p);return -1;}popup("Saved %s.bin (%lu bytes)",name,(unsigned long)want);free(d);}
    free(p);return 0;
}

static int extract_epk2(FILE *f,const char *outdir,int dump,const char *prefix){
    popup("EPK2: reading header at offset %u (%u bytes)",SIG,EPK2_HDR);
    unsigned char *stored=read_alloc(f,SIG,EPK2_HDR); if(!stored){errp("EPK2: failed reading main header");return -1;}
    unsigned char *hdr=NULL; const epk_key_t *key=NULL;

    if(!memcmp(stored,"epak",4)){
        hdr=stored;
        printf("Header is not encrypted.\n");popup("EPK2: header not encrypted");
    } else {
        printf("Header is encrypted; finding key...\n");popup("EPK2: header encrypted, trying %u keys...",(unsigned)EPK_KEY_COUNT);
        key=find_key(stored,EPK2_HDR,"epak");
        if(!key){free(stored);errp("No valid EPK key found\n");return -1;}
        printf("Found valid key: %s\n",key->name);popup("EPK2 key found: %s",key->name);
        hdr=aes_ecb_dec(stored,EPK2_HDR,key->key,key->len);
        free(stored);
        if(!hdr)return -1;
    }

    uint32_t file_size=rd32le(hdr+4), count=rd32le(hdr+8);
    char ota[64]; trimstr(hdr+20,32,ota,sizeof(ota));
    printf("EPK2: Data size:%lu Pak count:%lu OTA ID:%s Version:%02x.%02x.%02x.%02x\n",
           (unsigned long)file_size,(unsigned long)count,ota,hdr[19],hdr[18],hdr[17],hdr[16]);
    popup("EPK2 v%02x.%02x.%02x.%02x OTA:%s - %u paks",hdr[19],hdr[18],hdr[17],hdr[16],ota,count);

    typedef struct { uint32_t off,size,seg; char name[8]; } P;
    if(count==0 || count>100000){free(hdr);errp("Invalid EPK2 pak count: %u\n",count);return -1;}
    P *ps=calloc(count,sizeof(P));
    if(!ps){free(hdr);return -1;}

    size_t pos=52;
    popup("EPK2: parsing %u pak table entries",count);
    for(uint32_t i=0;i<count;i++){
        if(pos+20>EPK2_HDR){free(ps);free(hdr);errp("EPK2 header is too small for %u packages\n",count);return -1;}
        ps[i].off=rd32le(hdr+pos)+SIG;
        ps[i].size=rd32le(hdr+pos+4);
        copy_name(hdr+pos+8,4,ps[i].name,sizeof(ps[i].name));
        ps[i].seg=rd32le(hdr+pos+16);
        pos+=20;
        printf("Pak %lu - %s, offset: %lu, size: %lu, segment size: %lu\n",
               (unsigned long)(i+1),ps[i].name,(unsigned long)ps[i].off,(unsigned long)ps[i].size,(unsigned long)ps[i].seg);
    }

    if(mkdir_p(outdir)){perr("Create output folder");free(ps);free(hdr);return -1;}
    uint32_t signature_count=0;

    for(uint32_t n=0;n<count;n++){
        /* Rust reference: actual_offset = pak.offset + 128 * signature_count. */
        uint64_t actual=(uint64_t)ps[n].off + (uint64_t)SIG*signature_count;
        popup("Pak %u/%u %s: seek offset=%llu (base=%u signatures=%u)",n+1,count,ps[n].name,(unsigned long long)actual,ps[n].off,signature_count);
        if(actual > 0x7fffffffULL || fseek(f,(long)actual,SEEK_SET)!=0){errp("EPK2 pak %s: seek failed at offset %llu: %s",ps[n].name,(unsigned long long)actual,strerror(errno));free(ps);free(hdr);return -1;}

        unsigned char signature[SIG];
        size_t sigread=fread(signature,1,SIG,f);
        if(sigread!=SIG){errp("EPK2 pak %s: signature short read at offset %llu (wanted %u got %u, EOF=%d, error=%d)",ps[n].name,(unsigned long long)actual,SIG,(unsigned)sigread,feof(f),ferror(f));free(ps);free(hdr);return -1;}
        signature_count++;

        unsigned char encrypted_header[128];
        long header_off=ftell(f);
        size_t hdrread=fread(encrypted_header,1,128,f);
        if(hdrread!=128){errp("EPK2 pak %s: header short read at offset %ld (wanted 128 got %u, EOF=%d error=%d)",ps[n].name,header_off,(unsigned)hdrread,feof(f),ferror(f));free(ps);free(hdr);return -1;}

        if(!key){
            printf("\nFinding key...\n");
            key=find_key(encrypted_header,128,ps[n].name);
            if(!key){errp("No valid key found for package %s\n",ps[n].name);free(ps);free(hdr);return -1;}
            printf("Found correct key: %s\n",key->name);popup("EPK2 key found: %s",key->name);
        }

        unsigned char *ph=aes_ecb_dec(encrypted_header,128,key->key,key->len);
        if(!ph){free(ps);free(hdr);return -1;}

        uint32_t image=rd32le(ph+4), segcount=rd32le(ph+84), segsize=rd32le(ph+88), segidx=rd32le(ph+92);
        char plat[80]; trimstr(ph+8,64,plat,sizeof(plat));
        printf("\n(%lu/%lu) - %s, Size: %lu, Segment count: %lu, Platform: %s\n",
               (unsigned long)(n+1),(unsigned long)count,ps[n].name,(unsigned long)image,(unsigned long)segcount,plat);
        popup("Pak %u/%u: %s - %u bytes, %u segments, plat:%s",n+1,count,ps[n].name,image,segcount,plat);
        uint64_t written=0;

        if(segcount==0 || segcount>100000){errp("Invalid segment count for %s\n",ps[n].name);free(ph);free(ps);free(hdr);return -1;}
        if(segidx!=0){free(ph);free(ps);free(hdr);errp("Unexpected first segment index: %u\n",segidx);return -1;}

        char path[4096];
        snprintf(path,sizeof(path),"%s/%s.bin",outdir,ps[n].name);
        FILE *o=fopen(path,"wb");
        if(!o){perr(path);free(ph);free(ps);free(hdr);return -1;}

        for(uint32_t i=0;i<segcount;i++){
            if(i>0){
                long segsig_off=ftell(f);
                unsigned char segsig[SIG];
                size_t ssread=fread(segsig,1,SIG,f);
                if(ssread!=SIG){errp("EPK2 %s segment %u: signature short read at offset %ld (wanted %u got %u, EOF=%d error=%d)",ps[n].name,i+1,segsig_off,SIG,(unsigned)ssread,feof(f),ferror(f));fclose(o);free(ph);free(ps);free(hdr);return -1;}
                signature_count++;

                long eh_off=ftell(f);
                unsigned char eh[128];
                size_t ehread=fread(eh,1,128,f);
                if(ehread!=128){errp("EPK2 %s segment %u: header short read at offset %ld (wanted 128 got %u, EOF=%d error=%d)",ps[n].name,i+1,eh_off,(unsigned)ehread,feof(f),ferror(f));fclose(o);free(ph);free(ps);free(hdr);return -1;}
                free(ph);
                ph=aes_ecb_dec(eh,128,key->key,key->len);
                if(!ph){fclose(o);free(ps);free(hdr);return -1;}
                segcount=rd32le(ph+84);
                segsize=rd32le(ph+88);
                segidx=rd32le(ph+92);
                if(segidx!=i){errp("Unexpected segment index in pak header: expected %u got %u\n",i,segidx);fclose(o);free(ph);free(ps);free(hdr);return -1;}
            }

            /* Match the Rust reference exactly: segment_size is the normal
               segment size, while the final segment may use the distance to
               the next PAK as its actual stored length. AES-ECB decrypts full
               blocks and leaves any trailing partial bytes untouched. */
            uint64_t plain_size=segsize;
            uint64_t enc_size=plain_size;
            if(i==segcount-1 && n<count-1){
                uint64_t next=(uint64_t)ps[n+1].off + (uint64_t)SIG*signature_count;
                long cur=ftell(f);
                if(cur<0){perr("tell EPK2");fclose(o);free(ph);free(ps);free(hdr);return -1;}
                uint64_t distance=(next>(uint64_t)cur)?next-(uint64_t)cur:0;
                if(distance < plain_size){
                    errp("Invalid EPK2 encrypted segment length: stored=%llu plain=%llu\n",
                            (unsigned long long)distance,(unsigned long long)plain_size);
                    fclose(o);free(ph);free(ps);free(hdr);return -1;
                }
                enc_size=distance;
            }
            long data_off=ftell(f);
            popup("EPK2 %s seg %u/%u: data off=%ld plain=%llu stored=%llu key=%s",ps[n].name,i+1,segcount,data_off,(unsigned long long)plain_size,(unsigned long long)enc_size,key?key->name:"(none)");
            printf("- Segment %lu/%lu - Size: %llu%s\n",(unsigned long)(i+1),(unsigned long)segcount,
                   (unsigned long long)plain_size, enc_size!=plain_size?" (stored length differs)":"");
            if(plain_size==0 || plain_size>(uint64_t)SIZE_MAX || enc_size>(uint64_t)SIZE_MAX){
                errp("Invalid EPK2 segment size\n");fclose(o);free(ph);free(ps);free(hdr);return -1;
            }
            /* Stream the segment in small chunks: the DS cannot allocate a
               multi-megabyte segment buffer. AES-ECB blocks are independent,
               so every full 4096-byte chunk can be decrypted separately. */
            enum { STREAM_CHUNK = 65536 };
            unsigned char *chunk = (unsigned char *)malloc(STREAM_CHUNK);
            if(!chunk){errp("EPK2 %s seg %u: malloc failed for %u-byte streaming buffer",ps[n].name,i+1,(unsigned)STREAM_CHUNK);fclose(o);free(ph);free(ps);free(hdr);return -1;}
            uint64_t remaining = enc_size;
            uint64_t total_read = 0;
            unsigned last_pct_drawn = 999;
            while(remaining > 0){
                size_t want = remaining > STREAM_CHUNK ? STREAM_CHUNK : (size_t)remaining;
                size_t got = fread(chunk,1,want,f);
                if(got != want){
                    errp("EPK2 %s seg %u: streaming read failed at offset %ld (wanted %u got %u, EOF=%d error=%d)",ps[n].name,i+1,data_off+(long)total_read,(unsigned)want,(unsigned)got,feof(f),ferror(f));
                    free(chunk);fclose(o);free(ph);free(ps);free(hdr);return -1;
                }
                if(aes_ecb_decrypt_inplace(chunk,got,key->key,key->len)!=0){
                    errp("EPK2 %s seg %u: AES decrypt failed at segment byte %llu",ps[n].name,i+1,(unsigned long long)total_read);
                    free(chunk);fclose(o);free(ph);free(ps);free(hdr);return -1;
                }
                size_t out_written = fwrite(chunk,1,got,o);
                if(out_written != got){
                    errp("EPK2 %s seg %u: output write failed at segment byte %llu (wanted %u wrote %u errno=%d: %s)",ps[n].name,i+1,(unsigned long long)total_read,(unsigned)got,(unsigned)out_written,errno,strerror(errno));
                    free(chunk);fclose(o);free(ph);free(ps);free(hdr);return -1;
                }
                total_read += got;
                remaining -= got;
                unsigned pct = enc_size ? (unsigned)((total_read * 100ULL) / enc_size) : 100;
                /* Refresh every 5 percent to avoid slowing down SD streaming. */
                if(pct >= 100 || pct / 5 != last_pct_drawn / 5){
                    draw_stream_progress(ps[n].name, i+1, segcount, total_read, enc_size);
                    last_pct_drawn = pct;
                }
                unsigned previous_pct = enc_size ? (unsigned)(((total_read-got) * 100ULL) / enc_size) : 0;
                if(pct == 100 || pct / 10 != previous_pct / 10){
                    char progress_msg[120];
                    snprintf(progress_msg, sizeof(progress_msg), "%.12s S%lu/%lu %u%%", ps[n].name, (unsigned long)(i+1), (unsigned long)segcount, pct);
                    log_progress_bottom(progress_msg);
                    if(sd_log_file){
                        fprintf(sd_log_file, "PROGRESS: %s segment %lu/%lu %u%% (%lu/%lu bytes)\n", ps[n].name, (unsigned long)(i+1), (unsigned long)segcount, pct, (unsigned long)total_read, (unsigned long)enc_size);
                        fflush(sd_log_file);
                    }
                }
            }
            free(chunk);
            printf("-- Streamed and saved %llu bytes!\n",(unsigned long long)enc_size);
            written+=enc_size; progress("Extracting",ps[n].name,i,segcount);
        }
        if(fflush(o)!=0)errp("EPK2 %s: fflush failed errno=%d: %s",ps[n].name,errno,strerror(errno));
        if(fclose(o)!=0){errp("EPK2 %s: close output failed errno=%d: %s",ps[n].name,errno,strerror(errno));free(ph);free(ps);free(hdr);return -1;}
        free(ph);
        popup("Saved %s.bin (%llu bytes)",ps[n].name,(unsigned long long)written);
    }

    if(dump){(void)prefix;}
    free(ps);free(hdr);return 0;
}
static int is_epk3_pattern(FILE *f){return is_epk3(f);}
static int extract_epk3(FILE *f,const char *outdir,int dump){
    unsigned char *stored=read_alloc(f,0,EPK3_HDR);if(!stored){errp("EPK3: cannot read header; file may be truncated");return -1;} const epk_key_t *key=NULL; unsigned char *hdr=NULL; int nw=0;
    key=find_key(stored+128,EPK3_HDR-128,"EPK3"); unsigned sig=128; if(key){hdr=aes_ecb_dec(stored+128,EPK3_HDR-128,key->key,key->len);} else {key=find_key(stored+256,EPK3_HDR-256,"EPK3");if(key){nw=1;sig=256;hdr=aes_ecb_dec(stored+256,EPK3_HDR-256,key->key,key->len);}}
    free(stored);if(!key||!hdr){errp("No valid EPK3 key found\n");free(hdr);return -1;}printf("Found valid EPK3 key: %s (%s type)\n",key->name,nw?"new":"old");popup("EPK3 key found: %s (%s type)",key->name,nw?"new":"old");uint32_t pkginfo=rd32le(hdr+40);char ota[64];trimstr(hdr+8,32,ota,sizeof(ota));printf("EPK3 OTA ID:%s Version:%02x.%02x.%02x.%02x Package Info:%lu\n",ota,hdr[7],hdr[6],hdr[5],hdr[4],(unsigned long)pkginfo);popup("EPK3 v%02x.%02x.%02x.%02x OTA:%s",hdr[7],hdr[6],hdr[5],hdr[4],ota);
    unsigned char pv[36];if(read_at(f,1712,pv,36)){free(hdr);return -1;} uint64_t pos=1712+36+sig; unsigned char *pi_enc=read_alloc(f,pos,pkginfo);if(!pi_enc){free(hdr);return -1;}unsigned char *pi=aes_ecb_dec(pi_enc,pkginfo,key->key,key->len);free(pi_enc);if(!pi){free(hdr);return -1;}uint32_t list=rd32le(pi), cnt=rd32le(pi+4);printf("Package info list:%lu count:%lu\n",(unsigned long)list,(unsigned long)cnt);popup("EPK3: %u packages",cnt);size_t pp=8;if(nw)pp+=4; if(mkdir_p(outdir)){perr("Create output folder");free(pi);free(hdr);return -1;} uint32_t pak=1, extra=nw?4:0;
    while(pp+324<=pkginfo){char name[160];trimstr(pi+pp+8,128,name,sizeof(name));safe_name(name);uint32_t psize=rd32le(pi+pp+296), segidx=rd32le(pi+pp+308), segcount=rd32le(pi+pp+312), segsize=rd32le(pi+pp+316);if(!name[0])break;printf("(%lu) %s Size:%lu Segments:%lu\n",(unsigned long)pak,name,(unsigned long)psize,(unsigned long)segcount);popup("Pak %lu/%lu: %s - %lu bytes, %lu segments",(unsigned long)pak,(unsigned long)cnt,name,(unsigned long)psize,(unsigned long)segcount);pak++;char path[4096];snprintf(path,sizeof(path),"%s/%s.bin",outdir,name);FILE *o=fopen(path,"wb");if(!o){perr(path);free(pi);free(hdr);return -1;}for(uint32_t i=0;i<segcount;i++){if(i>0){pp+=324;if(pp+324>pkginfo){fclose(o);free(pi);free(hdr);return -1;}segidx=rd32le(pi+pp+308);segsize=rd32le(pi+pp+316);}if(segidx!=i){errp("Unexpected EPK3 segment index\n");fclose(o);free(pi);free(hdr);return -1;}if(read_at(f,pos,NULL,0)){} unsigned char *sg=read_alloc(f,pos,sig);if(!sg){fclose(o);free(pi);free(hdr);return -1;}free(sg);pos+=sig;unsigned char *enc=read_alloc(f,pos,(size_t)segsize+extra);if(!enc){fclose(o);free(pi);free(hdr);return -1;}unsigned char *dec=aes_ecb_dec(enc,(size_t)segsize+extra,key->key,key->len);free(enc);if(!dec){fclose(o);free(pi);free(hdr);return -1;}if(fwrite(dec+extra,1,segsize,o)!=segsize){free(dec);fclose(o);free(pi);free(hdr);return -1;}free(dec);pos+=segsize+extra;printf(" Segment %lu/%lu Size:%lu\n",(unsigned long)(i+1),(unsigned long)segcount,(unsigned long)segsize);progress("Extracting",name,i,segcount);}fclose(o);popup("Saved %s.bin",name);pp+=324;}
    free(pi);free(hdr);(void)dump;return 0;
}


#if defined(SLOPEPK_PS5)
/* PS5 homebrew CLI frontend. Input and output paths can be supplied as argv. */
static void draw_stream_progress(const char *pak, uint32_t seg, uint32_t seg_total, uint64_t done, uint64_t total){
    unsigned pct = total ? (unsigned)((done * 100ULL) / total) : 100;
    if (pct > 100) pct = 100;
    printf("[progress] %s segment %u/%u: %u%% (%llu/%llu bytes)\n", pak,
           seg, seg_total, pct, (unsigned long long)done, (unsigned long long)total);
}
static void log_progress_bottom(const char *message){ puts(message); }
static void popup(const char *fmt, ...){
    char m[512]; va_list ap; va_start(ap,fmt); vsnprintf(m,sizeof(m),fmt,ap); va_end(ap);
    puts(m);
    if (sd_log_file) { fprintf(sd_log_file, "%s\n", m); fflush(sd_log_file); }
}
static void errp(const char *fmt, ...){
    char m[512]; va_list ap; va_start(ap,fmt); vsnprintf(m,sizeof(m),fmt,ap); va_end(ap);
    fprintf(stderr, "ERROR: %s\n", m);
    if (sd_log_file) { fprintf(sd_log_file, "ERROR: %s\n", m); fflush(sd_log_file); }
}
static void perr(const char *what){ errp("%s: %s",what,strerror(errno)); }

int main(int argc, char **argv){
    const char *input = argc > 1 ? argv[1] : "/data/slopepk/input.epk";
    const char *outdir = argc > 2 ? argv[2] : "/data/slopepk/output";
    char selected_input[4096];
    if (strlen(input) >= sizeof(selected_input)) { errp("Input path is too long"); return 2; }
    strcpy(selected_input, input);

    /* The log is best-effort: custom paths may be used on runtimes without /data. */
    if (mkdir_p("/data/slopepk") == 0 || errno == EEXIST)
        sd_log_file = fopen("/data/slopepk/slopepk.log", "w");
    popup("SlopePK PS5 EPK extractor");
    popup("Input: %s", selected_input);
    popup("Output: %s", outdir);

    FILE *f = fopen(selected_input, "rb");
    if (!f) { perr("Cannot open input EPK"); if(sd_log_file) fclose(sd_log_file); return 1; }
    int rc = -1;
    if (is_epk1(f)) { popup("Detected EPK1 format"); rc = extract_epk1(f, outdir); }
    else if (is_epk2(f)) { popup("Detected EPK2 format"); rc = extract_epk2(f, outdir, 0, "header"); }
    else if (is_epk3_pattern(f)) { popup("Detected EPK3 format"); rc = extract_epk3(f, outdir, 0); }
    else errp("Unsupported EPK format/header");
    fclose(f);
    if (rc == 0) popup("Extraction completed successfully");
    else errp("Extraction failed; see /data/slopepk/slopepk.log");
    popup("Log: /data/slopepk/slopepk.log");
    if (sd_log_file) { fclose(sd_log_file); sd_log_file = NULL; }
    return rc == 0 ? 0 : 1;
}

#elif defined(SLOPEPK_3DS)
/* Nintendo 3DS dual-screen UI and SD browser (libctru). */
static PrintConsole topScreen;
static PrintConsole bottomScreen;
static void ui_wait_frame(void);

#define LOG_LINES 7
#define LOG_WIDTH 31
static char ui_log[LOG_LINES][LOG_WIDTH + 1];
static unsigned ui_log_count;
/* Draw byte-level progress on the top screen without touching input handling. */
static void draw_stream_progress(const char *pak, uint32_t seg, uint32_t seg_total, uint64_t done, uint64_t total){
    unsigned pct = total ? (unsigned)((done * 100ULL) / total) : 100;
    if(pct > 100) pct = 100;
    consoleSelect(&topScreen);
    consoleClear();
    iprintf("SLOPEPK 3DS  |  EXTRACTING\n================================\n\n");
    iprintf("FILE\n%.28s\n\n", pak);
    iprintf("SEGMENT  %lu / %lu\n", (unsigned long)seg, (unsigned long)seg_total);
    iprintf("--------------------------------\n");
    iprintf("PROGRESS             %3u%%\n[", pct);
    unsigned filled = pct * 28 / 100;
    for(unsigned i=0;i<28;i++) iprintf(i<filled ? "#" : ".");
    iprintf("]\n\n");
    iprintf("READ  %lu KB\n", (unsigned long)(done/1024ULL));
    iprintf("SIZE  %lu KB\n", (unsigned long)(total/1024ULL));
    iprintf("\nProcessing encrypted data...\n");
    ui_wait_frame();
}

static void draw_logs_one(PrintConsole *screen, const char *heading){
    consoleSelect(screen);
    consoleClear();
    iprintf("SlopePK 3DS - LOG\n-------------------------------\n%s\n", heading);
    unsigned shown = ui_log_count < LOG_LINES ? ui_log_count : LOG_LINES;
    unsigned first = ui_log_count > LOG_LINES ? ui_log_count - LOG_LINES : 0;
    for(unsigned i=0;i<shown;i++) iprintf("%-31.31s\n", ui_log[(first+i)%LOG_LINES]);
}
/* Add extraction milestones to the rolling bottom-screen log while preserving
   the live progress display on the top screen. */
static void log_progress_bottom(const char *message){
    unsigned slot = ui_log_count % LOG_LINES;
    snprintf(ui_log[slot], sizeof(ui_log[slot]), "%.31s", message);
    ui_log_count++;
    draw_logs_one(&bottomScreen, "EXTRACTION LOG");
}
static void log_message(const char *message){
    unsigned slot = ui_log_count % LOG_LINES;
    snprintf(ui_log[slot], sizeof(ui_log[slot]), "%.31s", message);
    ui_log_count++;
    /* Keep the full, untruncated message on the SD card; screen text is shorter. */
    if (sd_log_file) {
        fprintf(sd_log_file, "%s\n", message);
        fflush(sd_log_file);
    }
    draw_logs_one(&topScreen, "TOP SCREEN");
    draw_logs_one(&bottomScreen, "BOTTOM SCREEN");
}
static void popup(const char *fmt, ...){
    char m[240]; va_list ap; va_start(ap,fmt); vsnprintf(m,sizeof(m),fmt,ap); va_end(ap);
    log_message(m);
}
static void errp(const char *fmt, ...){
    char m[240], line[240]; va_list ap; va_start(ap,fmt); vsnprintf(m,sizeof(m),fmt,ap); va_end(ap);
    snprintf(line,sizeof(line),"ERROR: %.220s",m);
    log_message(line);
}
static void perr(const char *what){ errp("%s: %s",what,strerror(errno)); }

#define MAX_ENTRIES 96
struct entry { char name[128]; int dir; };
static struct entry entries[MAX_ENTRIES];
static int entry_count;
static void join_path(char *out,size_t cap,const char *dir,const char *name){
    size_t n=strlen(dir); snprintf(out,cap,"%s%s%s",dir,(n && dir[n-1]=='/')?"":"/",name);
}
static int is_epk_name(const char *s){ size_t n=strlen(s); return n>=4 && (s[n-4]=='.') && (tolower((unsigned char)s[n-3])=='e') && (tolower((unsigned char)s[n-2])=='p') && (tolower((unsigned char)s[n-1])=='k'); }
static void scan_dir(const char *path){
    DIR *d=opendir(path); struct dirent *de; entry_count=0;
    if(!d){ errp("Cannot list folder: %s",path); return; }
    while((de=readdir(d)) && entry_count<MAX_ENTRIES){
        if(!strcmp(de->d_name,"."))continue;
        char full[512]; struct stat st; join_path(full,sizeof(full),path,de->d_name);
        if(stat(full,&st)!=0)continue;
        int isdir=S_ISDIR(st.st_mode);
        if(!isdir && !is_epk_name(de->d_name))continue;
        if(!strcmp(de->d_name,"..") && !strcmp(path,"sdmc:/"))continue;
        strncpy(entries[entry_count].name,de->d_name,sizeof(entries[entry_count].name)-1);
        entries[entry_count].name[sizeof(entries[entry_count].name)-1]=0;
        entries[entry_count].dir=isdir; entry_count++;
    }
    closedir(d);
}
static void draw_picker_header(const char *cwd, const char *selected_name){
    consoleSelect(&topScreen); consoleClear();
    iprintf("SlopePK 3DS\nChoose EPK to extract\n-------------------------------\n\nFolder:\n%.31s\n\nSelected:\n%.31s\n\nD-PAD UP/DOWN: move\nA: open/select\nB: go back\nSTART: quit", cwd, selected_name && selected_name[0] ? selected_name : "(none)");
}
/* Log input without redrawing either console: log_message() clears both
   screens, which must not happen in the middle of a button interaction. */
static void log_input(const char *action, int keys){
    if (sd_log_file) {
        fprintf(sd_log_file, "INPUT: %s (keys=0x%04X)\n", action, (unsigned)keys);
        fflush(sd_log_file);
    }
}

static int choose_epk(char *selected,size_t cap){
    char cwd[256]="sdmc:/";
    int cursor=0, top=0;
    unsigned repeat_wait=0;
    int refresh_entries=1;
    for(;;){
        if(refresh_entries){ scan_dir(cwd); refresh_entries=0; }
        if(cursor>=entry_count) cursor=entry_count?entry_count-1:0;
        if(cursor<0) cursor=0;
        char picked[128]="(none)";
        if(entry_count) snprintf(picked,sizeof(picked),"%s%s",entries[cursor].name,entries[cursor].dir?"/":"");
        draw_picker_header(cwd,picked);
        consoleSelect(&bottomScreen); consoleClear();
        iprintf("SD FILE EXPLORER\n-------------------------------\nPath: %.31s\n\n",cwd);
        if(!entry_count) iprintf("(no EPK files or folders)\n");
        if(cursor<top) top=cursor;
        if(cursor>=top+14) top=cursor-13;
        for(int i=top;i<entry_count && i<top+14;i++)
            iprintf("%c %-27.27s%s\n",i==cursor?'>':' ',entries[i].name,entries[i].dir?"/":"");
        iprintf("\nA: open/select  B: back\nD-pad: move  START: quit\n");

        ui_wait_frame();
        hidScanInput();                         /* exactly once per frame */
        int pressed = hidKeysDown();
        int held = hidKeysHeld();

        if(pressed & KEY_START){ log_input("START - quit picker", pressed); return 0; }

        /* Move immediately on press, then repeat while held. */
        int direction = 0;
        if(pressed & KEY_UP) direction = -1;
        else if(pressed & KEY_DOWN) direction = 1;
        else if(held & (KEY_UP|KEY_DOWN)) {
            if(++repeat_wait >= 10) {
                repeat_wait = 6;
                if(held & KEY_UP) direction = -1;
                else if(held & KEY_DOWN) direction = 1;
            }
        } else repeat_wait = 0;
        if(direction && entry_count){
            int old=cursor;
            cursor += direction;
            if(cursor<0) cursor=0;
            if(cursor>=entry_count) cursor=entry_count-1;
            if(cursor!=old) log_input(direction<0?"D-pad UP":"D-pad DOWN", pressed);
        }

        if(pressed & KEY_B){
            log_input("B - back", pressed);
            if(strcmp(cwd,"sdmc:/")){
                char *slash=strrchr(cwd,'/');
                if(slash && slash>cwd+4) *slash=0;
                else strcpy(cwd,"sdmc:/");
                cursor=0; top=0; repeat_wait=0; refresh_entries=1;
            }
        }
        if((pressed & KEY_A) && entry_count){
            char full[512];
            join_path(full,sizeof(full),cwd,entries[cursor].name);
            log_input(entries[cursor].dir?"A - open folder":"A - select EPK", pressed);
            if(entries[cursor].dir){
                if(strlen(full)<sizeof(cwd)){
                    strncpy(cwd,full,sizeof(cwd)-1); cwd[sizeof(cwd)-1]=0;
                    cursor=0; top=0; repeat_wait=0; refresh_entries=1;
                }
            } else {
                strncpy(selected,full,cap-1); selected[cap-1]=0;
                if(sd_log_file){ fprintf(sd_log_file,"Selected input: %s\n",selected); fflush(sd_log_file); }
                return 1;
            }
        }
    }
}

/* libctru frame helper: flush the console and present the next frame. */
static void ui_wait_frame(void) {
    gfxFlushBuffers();
    gfxSwapBuffers();
    gspWaitForVBlank();
}

int main(void){
    gfxInitDefault();
    consoleInit(GFX_TOP, &topScreen);
    consoleInit(GFX_BOTTOM, &bottomScreen);
    popup("Starting SlopePK 3DS...");
    popup("SD card is mounted by libctru");
    if (mkdir_p("sdmc:/SlopePK") != 0 && errno != EEXIST) {
        errp("Cannot create output folder: %s", strerror(errno));
    }
    /* Open a persistent diagnostic log on the root of the SD card. */
    sd_log_file = fopen("sdmc:/slopepk.log", "w");
    if (!sd_log_file) {
        errp("Cannot create sdmc:/slopepk.log: %s", strerror(errno));
    } else {
        fprintf(sd_log_file, "=== SlopePK 3DS log ===\n");
        fflush(sd_log_file);
    }
    popup("SD mounted successfully");
    popup("Log: sdmc:/slopepk.log");
    sd_log_file = fopen("fat:/slopepk.log", "w");
    if (sd_log_file) { fprintf(sd_log_file, "=== SlopePK DS log ===\n"); fflush(sd_log_file); }
    char input[512]; if(!choose_epk(input,sizeof(input)))return 0;
    consoleSelect(&topScreen); consoleClear();
    iprintf("SlopePK 3DS\nConfirm extraction\n-------------------------------\n\nInput file:\n%.31s\n\nOutput folder:\nsdmc:/SlopePK\n\nA: extract\nB: cancel",input);
    consoleSelect(&bottomScreen); consoleClear();
    iprintf("FILE SELECTED\n-------------------------------\n%s\n\nOutput:\nsdmc:/SlopePK\n\nA: extract\nB: cancel",input);
    for(;;){ui_wait_frame();hidScanInput();int k=hidKeysDown();if(k&KEY_B)return 0;if(k&KEY_A)break;}
    ui_log_count=0; popup("Starting extraction"); popup("Input: %.25s",input);
    FILE *f=fopen(input,"rb"); if(!f){perr("Cannot open input EPK");for(;;){ui_wait_frame();hidScanInput();if(hidKeysDown()&KEY_START)return 1;}}
    if(fseek(f,0,SEEK_END)==0){long input_size=ftell(f);popup("Input size: %ld bytes",input_size);if(input_size>=0)popup("Input end offset: 0x%08lX",input_size);}
    else errp("Could not determine input size: %s",strerror(errno));
    clearerr(f);
    int rc=-1;
    if(is_epk1(f)){popup("Detected EPK1 format");rc=extract_epk1(f,"sdmc:/SlopePK");}
    else if(is_epk2(f)){popup("Detected EPK2 format");rc=extract_epk2(f,"sdmc:/SlopePK",0,"header");}
    else if(is_epk3_pattern(f)){popup("Detected EPK3 format");rc=extract_epk3(f,"sdmc:/SlopePK",0);}
    else errp("Unsupported EPK format/header");
    fclose(f);
    if(rc==0) popup("Extraction completed successfully");
    else errp("Extraction failed; review slopepk.log for details");
    popup("Output folder: sdmc:/SlopePK");
    popup("Log saved: sdmc:/slopepk.log");
    popup("Press START to exit");
    for(;;){ui_wait_frame();hidScanInput();if(hidKeysDown()&KEY_START)break;}
    if (sd_log_file) { fclose(sd_log_file); sd_log_file = NULL; }
    gfxExit();
    return rc?1:0;
}

#else
/* Nintendo DS UI and SD browser (libfat). */
/* DS build does not have a dedicated top-screen streaming progress UI. */
static void draw_stream_progress(const char *pak, uint32_t seg, uint32_t seg_total, uint64_t done, uint64_t total){
    (void)pak; (void)seg; (void)seg_total; (void)done; (void)total;
}
static void log_progress_bottom(const char *message){ popup("%s", message); }

static PrintConsole bottomScreen;
static void popup(const char *fmt, ...){
    char m[240]; va_list ap; va_start(ap,fmt); vsnprintf(m,sizeof(m),fmt,ap); va_end(ap);
    consoleSelect(&bottomScreen); iprintf("\x1b[22;0H%-31.31s",m);
}
static void errp(const char *fmt, ...){
    char m[240]; va_list ap; va_start(ap,fmt); vsnprintf(m,sizeof(m),fmt,ap); va_end(ap);
    consoleSelect(&bottomScreen); iprintf("\x1b[21;0HERROR: %-25.25s",m);
}
static void perr(const char *what){ errp("%s: %s",what,strerror(errno)); }

#define MAX_ENTRIES 96
struct entry { char name[128]; int dir; };
static struct entry entries[MAX_ENTRIES];
static int entry_count;
static void join_path(char *out,size_t cap,const char *dir,const char *name){
    size_t n=strlen(dir); snprintf(out,cap,"%s%s%s",dir,(n && dir[n-1]=='/')?"":"/",name);
}
static int is_epk_name(const char *s){ size_t n=strlen(s); return n>=4 && (s[n-4]=='.') && (tolower((unsigned char)s[n-3])=='e') && (tolower((unsigned char)s[n-2])=='p') && (tolower((unsigned char)s[n-1])=='k'); }
static void scan_dir(const char *path){
    DIR *d=opendir(path); struct dirent *de; entry_count=0;
    if(!d)return;
    while((de=readdir(d)) && entry_count<MAX_ENTRIES){
        if(!strcmp(de->d_name,"."))continue;
        char full[512]; struct stat st; join_path(full,sizeof(full),path,de->d_name);
        if(stat(full,&st)!=0)continue;
        int isdir=S_ISDIR(st.st_mode);
        if(!isdir && !is_epk_name(de->d_name))continue;
        if(!strcmp(de->d_name,"..") && !strcmp(path,"fat:/"))continue;
        strncpy(entries[entry_count].name,de->d_name,sizeof(entries[entry_count].name)-1);
        entries[entry_count].name[sizeof(entries[entry_count].name)-1]=0;
        entries[entry_count].dir=isdir; entry_count++;
    }
    closedir(d);
}
static int choose_epk(char *selected,size_t cap){
    char cwd[256]="fat:/"; int cursor=0, top=0;
    for(;;){
        scan_dir(cwd); if(cursor>=entry_count)cursor=entry_count?entry_count-1:0; if(cursor<0)cursor=0;
        consoleSelect(&bottomScreen); consoleClear();
        iprintf("SlopePK DS - choose EPK\nA: open/select  B: parent\nSTART: quit\nSD:%s\n\n",cwd);
        if(!entry_count)iprintf("(no EPK files or folders)\n");
        if(cursor<top)top=cursor; if(cursor>=top+14)top=cursor-13;
        for(int i=top;i<entry_count && i<top+14;i++) iprintf("%c %-27.27s%s\n",i==cursor?'>':' ',entries[i].name,entries[i].dir?"/":"");
        swiWaitForVBlank(); scanKeys(); int k=keysDownRepeat();
        if(k&KEY_START)return 0;
        if((k&KEY_UP)&&cursor>0)cursor--;
        if((k&KEY_DOWN)&&cursor+1<entry_count)cursor++;
        if(k&KEY_B){ if(strcmp(cwd,"fat:/")){ char *slash=strrchr(cwd,'/'); if(slash && slash>cwd+4)*slash=0; else strcpy(cwd,"fat:/"); cursor=0;} }
        if((k&KEY_A)&&entry_count){
            char full[512]; join_path(full,sizeof(full),cwd,entries[cursor].name);
            if(entries[cursor].dir){ if(strlen(full)<sizeof(cwd)){strncpy(cwd,full,sizeof(cwd)-1);cwd[sizeof(cwd)-1]=0;cursor=0;} }
            else { strncpy(selected,full,cap-1);selected[cap-1]=0; return 1; }
        }
    }
}
int main(void){
    videoSetMode(MODE_0_2D); videoSetModeSub(MODE_0_2D);
    vramSetBankA(VRAM_A_MAIN_BG); vramSetBankC(VRAM_C_SUB_BG);
    consoleInit(&bottomScreen,0,BgType_Text4bpp,BgSize_T_256x256,31,0,false,true);
    consoleSelect(&bottomScreen); consoleClear();
    iprintf("SlopePK DS\nEPK1 / EPK2 / EPK3 extractor\n\nMounting SD card...\n");
    if(!fatInitDefault()){ iprintf("SD mount failed. Check flashcart/SD.\n"); for(;;){swiWaitForVBlank();scanKeys();if(keysDown()&KEY_START)break;} return 1; }
    sd_log_file = fopen("fat:/slopepk.log", "w");
    if (sd_log_file) { fprintf(sd_log_file, "=== SlopePK DS log ===\n"); fflush(sd_log_file); }
    char input[512]; if(!choose_epk(input,sizeof(input)))return 0;
    consoleSelect(&bottomScreen); consoleClear(); iprintf("Selected:\n%s\n\nOutput: /SlopePK\nA: extract   B: cancel\n",input);
    for(;;){swiWaitForVBlank();scanKeys();int k=keysDown();if(k&KEY_B)return 0;if(k&KEY_A)break;}
    FILE *f=fopen(input,"rb"); if(!f){errp("Cannot open EPK file");for(;;){swiWaitForVBlank();scanKeys();if(keysDown()&KEY_START)return 1;}}
    int rc=-1;
    if(is_epk1(f))rc=extract_epk1(f,"fat:/SlopePK");
    else if(is_epk2(f))rc=extract_epk2(f,"fat:/SlopePK",0,"header");
    else if(is_epk3_pattern(f))rc=extract_epk3(f,"fat:/SlopePK",0);
    else errp("Unsupported EPK format");
    fclose(f); consoleSelect(&bottomScreen); consoleClear();
    iprintf("SlopePK DS\n\n%s\n\nOutput folder:\n/SlopePK\n\nPress START to exit.",rc==0?"Extraction complete!":"Extraction failed.");
    for(;;){swiWaitForVBlank();scanKeys();if(keysDown()&KEY_START)break;}
    if (sd_log_file) { fclose(sd_log_file); sd_log_file = NULL; }
    return rc?1:0;
}

#endif
