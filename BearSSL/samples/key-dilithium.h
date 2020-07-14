/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "bearssl.h"

/*
 * The private key for the server certificate (DILITHIUM).
 */

static const unsigned char DLTHM_RHO[] = {
        0x97, 0xBF, 0x25, 0x00, 0x1C, 0xD3, 0x77, 0x30, 0x91, 0x90, 0x8C, 0x69,
        0xBB, 0x3A, 0x12, 0xDE, 0x2D, 0x67, 0xAC, 0xD9, 0xE2, 0x73, 0x63, 0xDB,
        0x71, 0x03, 0xD6, 0x6E, 0x7C, 0x4C, 0x5F, 0xCA
};

static const unsigned char DLTHM_KEY[] = {
        0x4F, 0x3E, 0x1F, 0xF2, 0xF4, 0x26, 0x84, 0x86, 0x04, 0x63, 0xE3, 0x17,
        0x24, 0x33, 0xC3, 0x53, 0x9D, 0xF2, 0x92, 0xB6, 0xBA, 0x06, 0x5A, 0x0D,
        0x2F, 0xAA, 0xAD, 0x75, 0xB3, 0x8E, 0xD2, 0x18
};

static const unsigned char DLTHM_TR[] = {
        0xAF, 0x3C, 0xAD, 0xF2, 0xC0, 0x58, 0x29, 0x97, 0xD4, 0xAF, 0xC2, 0x39,
        0xF0, 0x08, 0x6C, 0xA1, 0x50, 0x1E, 0xFA, 0xD6, 0x0F, 0x49, 0xDB, 0x73,
        0x52, 0xF9, 0x66, 0x04, 0xF9, 0x8C, 0x88, 0x61, 0x56, 0x13, 0x9F, 0x59,
        0x41, 0x92, 0xCD, 0x68, 0x6F, 0x23, 0x92, 0x40, 0x2D, 0xB8, 0xA3, 0xD8
};

static const unsigned char DLTHM_S1[] = {
        0x1C, 0xB6, 0x00, 0x5A, 0xA4, 0x20, 0x33, 0xA9, 0x64, 0x91, 0x42, 0x1B,
        0x0C, 0xC8, 0x9A, 0xA4, 0x01, 0x61, 0x35, 0xE9, 0x32, 0x26, 0x4A, 0x75,
        0x84, 0x89, 0x99, 0xDD, 0xB4, 0x50, 0x2D, 0xA1, 0x26, 0x74, 0xA8, 0x45,
        0x58, 0x0B, 0x97, 0x03, 0xB1, 0x81, 0x58, 0xC8, 0xA4, 0x34, 0x65, 0x16,
        0x9D, 0xD3, 0x06, 0x01, 0xAC, 0x80, 0xB6, 0xCD, 0xD2, 0x66, 0x21, 0xD0,
        0x0E, 0x59, 0xB3, 0x84, 0x10, 0xD5, 0x02, 0x16, 0x02, 0xF2, 0x62, 0x2C,
        0x4A, 0xAD, 0x31, 0x18, 0x31, 0x62, 0xD3, 0xC0, 0xD2, 0xD0, 0x4A, 0x35,
        0xA9, 0x83, 0x6E, 0xC1, 0x04, 0xB2, 0x4B, 0x6D, 0xBB, 0x0C, 0xA3, 0xD4,
        0x86, 0xA9, 0x2E, 0xB1, 0x63, 0x16, 0x63, 0x86, 0xA6, 0x68, 0x9C, 0x00,
        0xDE, 0x18, 0x65, 0xE6, 0x34, 0xB5, 0xAB, 0xE3, 0x05, 0x76, 0x51, 0x72,
        0xE2, 0xC4, 0x95, 0x31, 0x5A, 0x53, 0x54, 0xD9, 0x24, 0x6A, 0x41, 0x89,
        0x46, 0x35, 0xD1, 0x55, 0x43, 0x03, 0x9C, 0x21, 0x06, 0x58, 0x57, 0x19,
        0x8A, 0x41, 0x82, 0x75, 0xBA, 0x10, 0x11, 0x57, 0x4C, 0x4A, 0x30, 0x45,
        0x75, 0x54, 0x39, 0x8C, 0xC9, 0x32, 0x14, 0x33, 0x78, 0x9A, 0xE6, 0x30,
        0x36, 0x59, 0xC9, 0x68, 0xE8, 0xBA, 0xD2, 0x88, 0x78, 0x51, 0xA8, 0x96,
        0x28, 0x0C, 0xCE, 0x65, 0x88, 0x85, 0x5A, 0x56, 0xB9, 0xF1, 0xB0, 0x91,
        0xDA, 0xE0, 0x32, 0x50, 0x21, 0xCB, 0x11, 0xB7, 0xBA, 0x13, 0x5A, 0x5A,
        0x13, 0x61, 0x0B, 0xA8, 0x91, 0x6C, 0x0D, 0x32, 0x58, 0xDD, 0x46, 0x9B,
        0x8C, 0x5C, 0x85, 0x4A, 0x3D, 0xA6, 0x55, 0x39, 0x90, 0x89, 0xD6, 0x30,
        0x2C, 0xAA, 0xA5, 0x0E, 0x58, 0x03, 0xA3, 0x2B, 0x3B, 0x6D, 0x15, 0x6E,
        0x65, 0xDA, 0x29, 0x96, 0x3A, 0x57, 0x41, 0x9A, 0x44, 0x36, 0xAD, 0x68,
        0x8C, 0x4C, 0xC7, 0xDA, 0x00, 0xB6, 0x5E, 0x33, 0x94, 0x51, 0xCA, 0x49,
        0x30, 0x6A, 0x26, 0xAE, 0xE3, 0xA2, 0x05, 0x9A, 0x62, 0x71, 0x40, 0xB8,
        0xD3, 0xA6, 0x42, 0xB0, 0x99, 0xA4, 0x25, 0xE2, 0xB1, 0xAC, 0x31, 0x9B,
        0x99, 0xDB, 0x44, 0x12, 0xB8, 0x0A, 0x98, 0xC2, 0xCC, 0x4B, 0x8C, 0x86,
        0x69, 0x6A, 0x66, 0x8E, 0x26, 0x7B, 0xD5, 0xB2, 0x58, 0x85, 0x02, 0x04,
        0x62, 0xB1, 0xBA, 0x2A, 0x19, 0x20, 0x06, 0xEB, 0x01, 0x99, 0x31, 0x70,
        0x65, 0xB7, 0x71, 0x75, 0xDB, 0x32, 0x4E, 0x92, 0x16, 0x10, 0xD9, 0xD1,
        0xE6, 0x2A, 0xB4, 0x41, 0x19, 0x4C, 0xAB, 0x30, 0x79, 0x41, 0x09, 0x38,
        0x43, 0x15, 0xC8, 0x45, 0x97, 0xAA, 0x4C, 0xD4, 0x9A, 0x53, 0x2D, 0x07,
        0x08, 0x3B, 0x82, 0x16, 0xCD, 0xA4, 0xCE, 0x2C, 0xA5, 0x12, 0x09, 0x70,
        0x92, 0x82, 0x06, 0x70, 0x36, 0x72, 0x86, 0x0C, 0x87, 0xA8, 0x4A, 0x72,
        0xC3, 0x5C, 0x26, 0x70, 0x16, 0xC6, 0x13, 0xD9, 0x79, 0x89, 0xBA, 0x95,
        0xD1, 0x52, 0x79, 0xC2, 0x16, 0x8E, 0x90, 0xE4, 0x4A, 0x12, 0xB6, 0x70,
        0x32, 0x43, 0xA6, 0x65, 0x4C, 0xAF, 0x26, 0xB1, 0x75, 0x51, 0x27, 0xCE,
        0x98, 0x20, 0xC5, 0x33, 0x04, 0x0B, 0x31, 0xE0, 0x16, 0xC3, 0x16, 0x11,
        0x23, 0x04, 0x36, 0x1D, 0x00, 0x0A, 0x52, 0xD0, 0x96, 0x10, 0x3B, 0xD2,
        0xDB, 0x56, 0x82, 0xB6, 0x94, 0xD8, 0xDA, 0xE4, 0xDA, 0x80, 0xB0, 0x1A,
        0xDA, 0xA0, 0x06, 0x18, 0xC4, 0xC9, 0x32, 0x3A, 0x6A, 0xA2, 0x23, 0x09,
        0x8A, 0x16, 0xD8, 0x6D, 0xB9, 0xD2, 0x76, 0xA6, 0x61, 0x6A, 0xBB, 0x7A
};

static const unsigned char DLTHM_S2[] = {
        0x64, 0x82, 0xC6, 0x50, 0x8D, 0x99, 0xD5, 0x52, 0x02, 0x10, 0x24, 0x75,
        0x20, 0x3D, 0xC3, 0x32, 0x20, 0xA1, 0x5D, 0x2B, 0xA6, 0x4A, 0x3D, 0x23,
        0x62, 0x2B, 0x6E, 0x84, 0x54, 0x4A, 0x46, 0xC3, 0x2D, 0xB4, 0xC2, 0x8E,
        0x0A, 0x40, 0x07, 0x95, 0x46, 0x43, 0x23, 0x62, 0x48, 0x54, 0xC1, 0x4C,
        0xA9, 0x33, 0x88, 0x96, 0x4D, 0xB6, 0x13, 0x2D, 0xD1, 0xD4, 0x60, 0x26,
        0x84, 0xB9, 0x06, 0x41, 0x0D, 0xD0, 0x10, 0xC0, 0x2C, 0x9B, 0x54, 0x96,
        0x91, 0x60, 0x31, 0xE0, 0x50, 0x74, 0x05, 0xC0, 0x65, 0x88, 0x13, 0x05,
        0x82, 0x8C, 0x26, 0x68, 0xE4, 0x0D, 0xD3, 0x60, 0x64, 0x8D, 0xD0, 0xC5,
        0x71, 0x05, 0x18, 0x33, 0x39, 0xC2, 0x15, 0x08, 0x4F, 0x06, 0xEB, 0x92,
        0xA1, 0xA6, 0x26, 0x4E, 0xED, 0x8D, 0x86, 0x9B, 0x54, 0x08, 0x47, 0xC5,
        0x12, 0xE1, 0x36, 0x41, 0x28, 0x7B, 0x8C, 0x4D, 0x48, 0x9A, 0x3A, 0xB2,
        0x41, 0xC6, 0x2D, 0x1A, 0x69, 0x46, 0x83, 0x62, 0xA9, 0xA4, 0xA2, 0x84,
        0x36, 0x41, 0x21, 0x8C, 0x03, 0xC5, 0x6C, 0x17, 0xA2, 0x8A, 0x18, 0xD4,
        0xEA, 0x30, 0x16, 0x19, 0x95, 0x36, 0x53, 0x96, 0x4D, 0x5A, 0xD4, 0x55,
        0x50, 0xD6, 0xC1, 0x4B, 0x63, 0x4A, 0xCD, 0xC8, 0x08, 0x22, 0x02, 0xDB,
        0x4D, 0x82, 0x58, 0x5A, 0x32, 0x79, 0xDA, 0x26, 0x93, 0x6E, 0x21, 0x59,
        0x55, 0xDC, 0x04, 0xCD, 0x36, 0x27, 0x45, 0x98, 0x84, 0xA1, 0x12, 0x12,
        0x1C, 0xA3, 0x92, 0x02, 0x31, 0xA6, 0x06, 0x60, 0xDB, 0x1D, 0x52, 0x8F,
        0x36, 0x67, 0x03, 0x33, 0x53, 0x55, 0x21, 0x53, 0xD3, 0x65, 0x95, 0x7A,
        0x88, 0xAC, 0x41, 0xC8, 0x86, 0xC5, 0x03, 0x27, 0xCF, 0x5D, 0xB7, 0x50,
        0x98, 0x18, 0x28, 0x8D, 0x43, 0x4D, 0x81, 0x9D, 0x24, 0x51, 0xE8, 0x34,
        0xD1, 0x16, 0x96, 0x71, 0x3D, 0x75, 0xD3, 0xEC, 0x22, 0x0A, 0xC5, 0x44,
        0x28, 0x9B, 0x22, 0x55, 0x51, 0x6A, 0xE5, 0x5A, 0x82, 0x85, 0x88, 0x2D,
        0x0E, 0xA6, 0x74, 0x18, 0x4B, 0x79, 0xDE, 0x0C, 0x44, 0x15, 0x3B, 0xC5,
        0xB2, 0xE2, 0x24, 0x24, 0xB4, 0x6C, 0x6B, 0xB7, 0xB1, 0x4E, 0xC6, 0x44,
        0x8D, 0x84, 0x55, 0x00, 0x54, 0x8D, 0x42, 0x64, 0x4C, 0x02, 0x60, 0x36,
        0x59, 0x60, 0x8B, 0xDD, 0x12, 0xCE, 0x42, 0xE0, 0x48, 0x1E, 0x46, 0xB3,
        0x25, 0x04, 0x4E, 0xEC, 0x54, 0x78, 0x0D, 0x55, 0x20, 0x63, 0xA9, 0xB8,
        0x90, 0xCC, 0x39, 0xEB, 0xAC, 0xD9, 0xAE, 0xAA, 0x72, 0x2E, 0x95, 0x1A,
        0x89, 0x69, 0x7B, 0x9B, 0xCA, 0x0A, 0x0E, 0xA7, 0xCC, 0xC1, 0x42, 0xB5,
        0x01, 0x9C, 0x29, 0x88, 0xD3, 0x0D, 0x1B, 0xC4, 0x56, 0x91, 0x59, 0xA6,
        0xB0, 0x91, 0x2D, 0x15, 0xEA, 0x84, 0x99, 0xB7, 0x12, 0x46, 0xC9, 0xBA,
        0x34, 0x3C, 0xA5, 0x08, 0x13, 0x59, 0x31, 0x40, 0x2C, 0xA6, 0x6C, 0x90,
        0x01, 0x91, 0x0C, 0x55, 0xC4, 0x61, 0x1E, 0x1A, 0x13, 0xAC, 0x49, 0x3B,
        0x46, 0x98, 0x04, 0xC2, 0x30, 0x56, 0xB5, 0x28, 0x37, 0xCA, 0xE8, 0x78,
        0x64, 0xAC, 0xB5, 0x73, 0xCC, 0x30, 0x58, 0x13, 0x90, 0xDB, 0x50, 0x63,
        0xD6, 0x26, 0x73, 0x88, 0xB3, 0x86, 0xD8, 0x92, 0x31, 0xE9, 0x16, 0x63,
        0xCB, 0x16, 0x00, 0xC5, 0xBC, 0x66, 0x5C, 0x33, 0xC9, 0x14, 0xA7, 0x50,
        0x00, 0xEA, 0x96, 0xDC, 0x02, 0xC7, 0x1A, 0x21, 0xD3, 0x8E, 0x2A, 0x88,
        0xE0, 0x2C, 0x09, 0x16, 0xB1, 0x5A, 0x2A, 0x19, 0x86, 0x32, 0x31, 0xDA,
        0x52, 0x88, 0x36, 0x60, 0xBD, 0x06, 0x33, 0x59, 0xB9, 0x6E, 0xD1, 0xD0,
        0x68, 0xB1, 0xB2, 0x30, 0x12, 0x4C, 0x76, 0x89, 0x26, 0x9E, 0x2C, 0x64,
        0x22, 0x00, 0x70, 0x86, 0x53, 0xD0, 0x40, 0x9A, 0x2C, 0x40, 0xC6, 0x4C,
        0xD1, 0xB4, 0x3A, 0x0B, 0x11, 0x2B, 0xD9, 0x3A, 0xB4, 0x0B, 0x1B, 0x21,
        0xB4, 0xC7, 0x6A, 0x10, 0x9D, 0x81, 0xF1, 0x52, 0x8C, 0x15, 0x2B, 0x29,
        0x1E, 0xA5, 0x48, 0x6A, 0xCD, 0x84, 0x83, 0x6A, 0x61, 0x25, 0x62, 0x8F,
        0x01, 0x19, 0xAE, 0x14, 0x2C, 0x50, 0xB1, 0x41, 0x57, 0xAD, 0x47, 0xB3,
        0x56, 0x54, 0x15, 0xAE, 0x41, 0x77, 0x18, 0x9A, 0x54, 0x9D, 0xD0, 0xB0
};

static const unsigned char DLTHM_T0[] = {
        0x12, 0x02, 0x0D, 0xDF, 0x4F, 0x0F, 0x5D, 0xD2, 0x5B, 0x62, 0x02, 0xF8,
        0xCA, 0x5B, 0xB7, 0x1B, 0x21, 0xE5, 0x42, 0x2A, 0xEF, 0x08, 0xC8, 0x28,
        0x2D, 0x72, 0x13, 0x9C, 0x5B, 0xFA, 0x4A, 0x18, 0x80, 0x39, 0xFF, 0x33,
        0xA5, 0xA4, 0x16, 0xAB, 0x79, 0xE7, 0x16, 0x30, 0xD5, 0xB3, 0xBE, 0x2F,
        0xC1, 0x7E, 0x5A, 0xD3, 0xDF, 0x91, 0x19, 0xED, 0x04, 0xFE, 0x46, 0x2A,
        0x8B, 0x27, 0x21, 0xCD, 0x9C, 0xA9, 0x3A, 0x61, 0x41, 0xB0, 0x25, 0x19,
        0xBF, 0x3D, 0x32, 0xEA, 0xA3, 0x52, 0xC5, 0xCA, 0x20, 0x4B, 0x39, 0xC0,
        0xCF, 0x8F, 0x6E, 0x3E, 0x71, 0x24, 0xFD, 0xE9, 0x7C, 0x5E, 0x27, 0x97,
        0xE3, 0xE1, 0xF5, 0x47, 0xCF, 0xBD, 0x07, 0x44, 0x38, 0xE4, 0xE7, 0xCD,
        0x1F, 0x51, 0x33, 0xB1, 0x14, 0xC7, 0x03, 0x38, 0x58, 0x76, 0x5C, 0xE5,
        0x94, 0xCF, 0xA5, 0xE2, 0x1A, 0xAC, 0x3C, 0x32, 0x55, 0x84, 0xD3, 0x2D,
        0x75, 0x24, 0x4B, 0xED, 0xA2, 0xA7, 0xA0, 0xF2, 0x3B, 0x3B, 0x68, 0xC2,
        0xD2, 0xCF, 0x43, 0x51, 0x11, 0x8D, 0xE4, 0x6D, 0x9F, 0xD7, 0xD3, 0x5B,
        0xB5, 0x6B, 0x12, 0x57, 0xBB, 0x0E, 0x49, 0x15, 0x0E, 0xD8, 0x80, 0x2E,
        0x40, 0xD6, 0xD4, 0xBE, 0xE0, 0xAB, 0x17, 0x39, 0xFC, 0xA4, 0xAC, 0xD7,
        0x40, 0x1D, 0xC1, 0x24, 0x95, 0x07, 0x62, 0xE2, 0xFA, 0xC2, 0x71, 0xBE,
        0xD9, 0x41, 0x96, 0x1C, 0x7E, 0x49, 0x83, 0xCB, 0x04, 0xFC, 0xBC, 0xF0,
        0x73, 0x51, 0x98, 0x9A, 0xAB, 0x3F, 0x9A, 0x19, 0x38, 0x57, 0x72, 0x10,
        0x53, 0xBA, 0xF2, 0x96, 0x71, 0xE5, 0x44, 0xC5, 0x13, 0x60, 0x46, 0xFC,
        0x6F, 0x66, 0xE0, 0x98, 0x19, 0x94, 0x22, 0x2F, 0x6D, 0x9C, 0x1D, 0xE8,
        0xE0, 0x4A, 0xCA, 0x7A, 0x77, 0xD5, 0xE6, 0x88, 0x4E, 0xDF, 0xEE, 0x88,
        0x6B, 0x7F, 0x09, 0xCF, 0xDE, 0x73, 0x6C, 0xFD, 0xE2, 0xAD, 0x42, 0x3A,
        0xD8, 0x40, 0x4C, 0xE5, 0x5E, 0x59, 0xAB, 0xF9, 0x2A, 0x6C, 0xF7, 0x9D,
        0x54, 0x77, 0x3D, 0xAC, 0x84, 0xF5, 0x74, 0xC0, 0x64, 0x4D, 0xA1, 0x30,
        0xE5, 0x91, 0x92, 0x62, 0xE6, 0x40, 0x53, 0x5A, 0xDC, 0xA4, 0x2D, 0xD6,
        0x76, 0x68, 0x55, 0xB8, 0xCE, 0xD6, 0x6B, 0x09, 0x83, 0xB4, 0x11, 0xDC,
        0x4C, 0xFE, 0xC9, 0x78, 0x61, 0x67, 0x3E, 0xA5, 0xA6, 0x77, 0x62, 0x5E,
        0x6D, 0xBA, 0x2A, 0x37, 0x33, 0x37, 0x51, 0x4E, 0x3C, 0xBB, 0x57, 0xEF,
        0xAF, 0x98, 0x89, 0xA5, 0xDD, 0x07, 0xD6, 0x56, 0xEA, 0x85, 0x5E, 0x8B,
        0x07, 0x2D, 0xCD, 0xDE, 0x68, 0xF0, 0x50, 0xE3, 0xF1, 0x42, 0x58, 0x2F,
        0x0D, 0x21, 0xB9, 0xC2, 0xBC, 0x8A, 0x7E, 0xDF, 0x22, 0xCD, 0x95, 0x2A,
        0xCC, 0x15, 0x94, 0x74, 0x7B, 0xAE, 0x61, 0x29, 0xE7, 0x17, 0x30, 0xB7,
        0x6D, 0x69, 0xB4, 0x6A, 0xF6, 0x43, 0x79, 0x4E, 0xDD, 0x56, 0x0E, 0xAC,
        0xA7, 0x22, 0x42, 0x15, 0x3D, 0x8B, 0x21, 0xBE, 0xF6, 0x92, 0x7C, 0xA6,
        0xF8, 0x6D, 0x2C, 0x54, 0x05, 0xDC, 0x7D, 0x60, 0xA2, 0x9A, 0xFD, 0x8E,
        0xDC, 0x86, 0x62, 0x58, 0x84, 0x3B, 0xBE, 0x93, 0x30, 0xD6, 0xBD, 0x2E,
        0x9A, 0x1B, 0x82, 0x22, 0x2B, 0x0C, 0x38, 0x6C, 0x84, 0xB3, 0x49, 0xD7,
        0xE0, 0x5D, 0x39, 0xCA, 0x29, 0x7C, 0x39, 0x49, 0xA2, 0xE9, 0x39, 0xDC,
        0xF5, 0x48, 0x6C, 0xEB, 0x4A, 0x42, 0x63, 0xD2, 0x27, 0x1F, 0x67, 0x01,
        0x3E, 0x51, 0x6E, 0x17, 0xBD, 0x89, 0xBB, 0x5D, 0x90, 0x36, 0x0C, 0x1D,
        0xE9, 0x22, 0x86, 0x71, 0x29, 0x5A, 0xCA, 0x91, 0x56, 0x0C, 0xDC, 0xEF,
        0xC8, 0xF4, 0x87, 0x74, 0x41, 0x48, 0xA1, 0x57, 0xF3, 0xEB, 0x39, 0xA5,
        0x8E, 0xCE, 0xFE, 0x9C, 0x97, 0x94, 0xF1, 0xA6, 0x4A, 0x77, 0x89, 0x56,
        0x46, 0x5C, 0xB7, 0x6F, 0x16, 0x4D, 0xCB, 0xE1, 0xA5, 0xA0, 0xCF, 0x1C,
        0xF9, 0xBD, 0xE4, 0x87, 0x3E, 0x50, 0x9C, 0x06, 0x22, 0x99, 0xC4, 0x0B,
        0x4E, 0xF8, 0x1A, 0x5E, 0x68, 0xAE, 0x26, 0xC1, 0xAC, 0x9E, 0xA2, 0x6E,
        0xD4, 0xBE, 0x9B, 0x22, 0x58, 0x81, 0x1F, 0x7E, 0x42, 0xE4, 0xA5, 0xA0,
        0x7E, 0x4B, 0x11, 0xB8, 0xCF, 0x31, 0xD4, 0x9A, 0xA4, 0xD8, 0xFA, 0x5F,
        0xBC, 0xE8, 0x23, 0xF7, 0xF8, 0x17, 0x8B, 0xC6, 0x29, 0xF7, 0xC8, 0x52,
        0x41, 0x45, 0x1B, 0x4E, 0xE1, 0x6B, 0x72, 0x60, 0x7E, 0x7B, 0xB7, 0x3A,
        0x94, 0x90, 0x81, 0xDD, 0x5B, 0x13, 0x27, 0x33, 0x91, 0xA8, 0x70, 0xD4,
        0x76, 0x7D, 0x9D, 0x75, 0x8E, 0x7F, 0xD0, 0xBA, 0xBA, 0xC1, 0x8E, 0x23,
        0x2D, 0x7C, 0x18, 0x5F, 0x45, 0xD2, 0x82, 0x30, 0x8A, 0xAF, 0x79, 0x18,
        0xBB, 0xCE, 0x3A, 0x94, 0x07, 0xB5, 0xAA, 0x38, 0x83, 0xE2, 0xE8, 0x6B,
        0xFD, 0x56, 0xD8, 0x9C, 0x9F, 0xEB, 0x51, 0xD4, 0x33, 0xD7, 0x5A, 0x88,
        0x3A, 0x70, 0xF2, 0xDC, 0x4E, 0x49, 0x08, 0x21, 0xF1, 0xF5, 0xA6, 0x0E,
        0x81, 0x80, 0xA4, 0xBC, 0xCA, 0x2E, 0x83, 0x71, 0xF0, 0x69, 0xBD, 0x18,
        0x44, 0xD6, 0xD1, 0x49, 0x67, 0x98, 0xC9, 0xCC, 0x30, 0x26, 0xF0, 0x12,
        0x88, 0x78, 0x24, 0x91, 0x71, 0xFC, 0x24, 0xFB, 0x91, 0xEA, 0x57, 0xC7,
        0x65, 0xFA, 0x36, 0xBE, 0x12, 0x66, 0x12, 0x9C, 0x0B, 0x8D, 0x14, 0xB9,
        0xD9, 0x0A, 0x5E, 0xCA, 0x23, 0xDE, 0x8E, 0xBA, 0x44, 0x63, 0xB6, 0xC1,
        0xD1, 0x56, 0x6E, 0x7B, 0x6B, 0x3B, 0xBE, 0x98, 0x81, 0x7D, 0xA7, 0xDD,
        0xCC, 0xE3, 0x10, 0xA3, 0x39, 0x9D, 0x39, 0x25, 0xF5, 0xCC, 0x7D, 0x97,
        0x0C, 0xA6, 0xA8, 0xDF, 0xDE, 0xC0, 0x38, 0x5C, 0xC9, 0x37, 0x27, 0xE5,
        0x69, 0x4A, 0xE8, 0x75, 0xF8, 0x91, 0x1A, 0x5A, 0xFF, 0xA0, 0x42, 0x06,
        0x38, 0x5D, 0xBE, 0xBA, 0xF0, 0xFF, 0x7A, 0x4B, 0xA7, 0x73, 0xB4, 0x23,
        0xA6, 0x66, 0x12, 0xFC, 0x9A, 0x03, 0xD8, 0xA3, 0xDA, 0x9D, 0xB9, 0xEE,
        0xE4, 0xEE, 0x84, 0xD6, 0xDC, 0x7D, 0x2C, 0xCD, 0x56, 0xD8, 0x75, 0xC0,
        0x95, 0x16, 0x29, 0x77, 0xD3, 0xBA, 0x40, 0x22, 0xB5, 0x67, 0xC0, 0xFE,
        0xFD, 0x91, 0xFF, 0x50, 0xD4, 0xD4, 0xFC, 0x41, 0xE8, 0x9B, 0xEF, 0xB5,
        0x19, 0x33, 0x71, 0xF2, 0xA3, 0x81, 0xF7, 0x93, 0x84, 0x44, 0xBD, 0xD2,
        0x81, 0x5B, 0xB4, 0xB8, 0x08, 0xD7, 0xE4, 0x26, 0xB2, 0xAF, 0x83, 0xA0,
        0xE9, 0xCE, 0x65, 0x99, 0xF9, 0x39, 0x3C, 0x32, 0x09, 0x0B, 0xE9, 0xDE,
        0xCF, 0x6D, 0xA7, 0xBC, 0x39, 0xA8, 0xB5, 0x04, 0x5C, 0xD6, 0x48, 0xBC,
        0x57, 0x0E, 0x4F, 0x2E, 0x63, 0x42, 0x2D, 0x61, 0x9C, 0x11, 0x39, 0x1E,
        0xFE, 0xB5, 0xF9, 0xC3, 0x95, 0xF5, 0xDC, 0xDB, 0x3B, 0x95, 0x6C, 0x92,
        0xE8, 0x63, 0xD4, 0x76, 0xEB, 0x98, 0x9B, 0x4C, 0xB5, 0x2D, 0xF8, 0x86,
        0xF7, 0x6F, 0x21, 0xFC, 0x70, 0x9C, 0xDB, 0x4E, 0xE7, 0xC0, 0x7B, 0x18,
        0xEB, 0x64, 0x6C, 0x15, 0x57, 0x13, 0x67, 0xA5, 0xAC, 0x6B, 0x75, 0x94,
        0xEC, 0x0A, 0xD0, 0x19, 0x48, 0x7A, 0x83, 0xEE, 0x52, 0x6F, 0x3D, 0x6A,
        0x32, 0xC7, 0x7D, 0xB0, 0xC8, 0x5E, 0x2D, 0x4F, 0x51, 0x1B, 0x96, 0xF5,
        0x5B, 0xED, 0x57, 0x70, 0xBE, 0x18, 0x74, 0x3C, 0x70, 0xAA, 0x53, 0x32,
        0x43, 0x0B, 0xC3, 0xAA, 0xF9, 0x4E, 0xD6, 0x4E, 0xE3, 0xAD, 0xEE, 0x63,
        0xA4, 0x5A, 0xAA, 0xEA, 0xA8, 0xF0, 0x98, 0x76, 0x48, 0x69, 0x73, 0x89,
        0xB1, 0x02, 0xF3, 0x79, 0x3A, 0x04, 0x0E, 0xB4, 0x19, 0x48, 0x1E, 0x2B,
        0x6A, 0x4D, 0x37, 0xFA, 0x14, 0xFA, 0xBE, 0x1A, 0x1D, 0x44, 0xB7, 0x9A,
        0xB3, 0xBD, 0xC2, 0xD4, 0x16, 0x49, 0x6C, 0xFB, 0xBF, 0xD0, 0x37, 0x24,
        0x0B, 0xB9, 0xB9, 0xB6, 0xA5, 0x6D, 0x6B, 0xE5, 0x83, 0x6B, 0x36, 0xEE,
        0xDE, 0xE2, 0x54, 0x59, 0x19, 0xC1, 0xDA, 0xBD, 0x57, 0xC6, 0x47, 0xAC,
        0x93, 0xEC, 0xCA, 0xDE, 0xD5, 0x9E, 0x9F, 0x7B, 0x69, 0x52, 0xB1, 0x30,
        0x2C, 0x24, 0x43, 0x05, 0x65, 0x1B, 0x4E, 0xDA, 0x19, 0x3C, 0x43, 0xCF,
        0xE2, 0xE1, 0x01, 0x47, 0xAD, 0xBE, 0xD5, 0xA3, 0x08, 0x23, 0xFB, 0x84,
        0xA1, 0x79, 0x43, 0xE5, 0x5A, 0xFD, 0x5B, 0x78, 0x77, 0xDA, 0xF3, 0xA6,
        0x72, 0x77, 0x4D, 0x5E, 0xE6, 0xA1, 0x6D, 0x11, 0x90, 0x37, 0x05, 0x91,
        0xFD, 0x21, 0xE2, 0x9F, 0x0F, 0x1A, 0xE1, 0xCB, 0x4C, 0xEC, 0xEE, 0xEB,
        0xA7, 0x47, 0xAE, 0x57, 0x39, 0xB8, 0xCD, 0x90, 0xF4, 0x8D, 0xCF, 0xE5,
        0x48, 0xD1, 0xA4, 0xB0, 0x35, 0x6B, 0x0A, 0x43, 0x72, 0x0B, 0xA3, 0xE8,
        0x7F, 0x4E, 0x94, 0x33, 0xC1, 0x4E, 0xF9, 0x1E, 0x57, 0x18, 0xEC, 0xB7,
        0x15, 0xF1, 0x62, 0x62, 0xA5, 0xA2, 0xA7, 0x21, 0xAA, 0x72, 0x20, 0x2B,
        0x3A, 0xA8, 0x08, 0x7B, 0x45, 0x51, 0x96, 0x7C, 0xAC, 0x0E, 0xF2, 0x30,
        0xEF, 0x9A, 0xC5, 0x27, 0xCD, 0x0E, 0xF7, 0x34, 0x78, 0x66, 0xC5, 0xE8,
        0x8E, 0x18, 0x92, 0x44, 0xF3, 0x40, 0x31, 0xAC, 0xF3, 0x68, 0xEE, 0x88,
        0xC5, 0x92, 0x61, 0x9E, 0xC5, 0x37, 0xE6, 0x58, 0xE9, 0xF1, 0x21, 0x6E,
        0x39, 0xD1, 0x3A, 0x96, 0xAB, 0x55, 0x8F, 0x96, 0x7B, 0xA0, 0xC4, 0x27,
        0x30, 0x70, 0xF1, 0xFE, 0x35, 0x21, 0x38, 0x22, 0x24, 0xB6, 0x70, 0xB7,
        0xBF, 0xB8, 0x7C, 0x72, 0x09, 0xDF, 0xDF, 0x4A, 0xD8, 0xA9, 0xC1, 0x62,
        0x90, 0x21, 0xD7, 0xC3, 0x30, 0x08, 0xE7, 0x00, 0xDF, 0x44, 0x3F, 0x62,
        0xAE, 0x28, 0x68, 0x63, 0xF4, 0x48, 0x35, 0x27, 0xEF, 0xAF, 0x2C, 0xAC,
        0x0B, 0xE9, 0x3D, 0x20, 0x9D, 0x03, 0x6F, 0x1E, 0xEE, 0x65, 0x0F, 0x8B,
        0xE6, 0x1E, 0x9B, 0x2E, 0x6B, 0xB2, 0xCB, 0xDD, 0x67, 0x80, 0x66, 0x62,
        0xD0, 0x30, 0xAE, 0x99, 0xE0, 0x36, 0x09, 0xD7, 0xED, 0x6B, 0x99, 0x4B,
        0xE9, 0xE2, 0x5F, 0xB1, 0x07, 0xCF, 0x11, 0x06, 0x5A, 0x6E, 0x44, 0x16,
        0x02, 0x36, 0x04, 0xC1, 0x20, 0x4E, 0xE8, 0x9E, 0x2B, 0x44, 0xD2, 0x6C,
        0x0B, 0x46, 0x3A, 0x52, 0xC8, 0xCA, 0x40, 0x3B, 0x12, 0x03, 0x9D, 0x15,
        0xCF, 0xE7, 0x87, 0xE6, 0x7A, 0x2B, 0x07, 0xA5, 0x76, 0x4D, 0xC9, 0xCE,
        0xB0, 0xC9, 0x3E, 0xB2, 0x81, 0x45, 0xC7, 0xD1, 0xD2, 0x1B, 0x63, 0x4C,
        0xC7, 0x80, 0x4C, 0xEB, 0x9A, 0xAB, 0x56, 0xA6, 0xF0, 0x48, 0xC5, 0xF4,
        0x17, 0xC7, 0xE2, 0x7D, 0x9A, 0x2B, 0x73, 0xE8, 0x74, 0xF3, 0x39, 0xB7,
        0x47, 0xD4, 0x9A, 0xAF, 0xB9, 0x20, 0x64, 0xCA, 0x13, 0xD7, 0x91, 0x8A,
        0x03, 0x11, 0xDD, 0xA4, 0x2E, 0xCF, 0x61, 0xBD, 0x14, 0x2A, 0x50, 0x51,
        0xEA, 0x02, 0x6A, 0xD3, 0x73, 0xB7, 0xCE, 0xF5, 0x02, 0x88, 0x7E, 0xB7,
        0xFE, 0x64, 0x26, 0x67, 0x7D, 0xB7, 0x4B, 0x3C, 0x12, 0xA2, 0x6B, 0xF2,
        0x4D, 0xC8, 0x0D, 0x18, 0x76, 0x4B, 0xA0, 0x61, 0x02, 0x71, 0x4E, 0x99,
        0xCB, 0xE8, 0x11, 0xAC, 0x53, 0x43, 0x36, 0x2A, 0x4A, 0x9A, 0x65, 0x46,
        0xD4, 0x47, 0x8A, 0x02, 0x08, 0xB2, 0x24, 0xA7, 0x5F, 0x44, 0x04, 0x54,
        0x33, 0x43, 0xA0, 0x41, 0x28, 0xF7, 0x5F, 0x52, 0x06, 0x80, 0xA9, 0x56,
        0x75, 0x91, 0x78, 0x3D, 0xF9, 0xB4, 0x85, 0x5D, 0xC4, 0xF9, 0x0F, 0xD6,
        0x42, 0xFC, 0x52, 0x28, 0xD9, 0xB1, 0x36, 0xA4, 0x63, 0x53, 0x87, 0xF0,
        0x8A, 0x55, 0xA1, 0xD6, 0xB6, 0x06, 0xCC, 0x38, 0xAF, 0x89, 0xBC, 0x07,
        0xCC, 0x32, 0x0A, 0x6B, 0xB2, 0x5A, 0xD9, 0x63, 0x40, 0x39, 0xCA, 0x38,
        0x0A, 0x4F, 0xAA, 0x3A, 0x5B, 0x7B, 0x50, 0xCE, 0x32, 0xD9, 0x86, 0x64,
        0xCE, 0xC1, 0xB9, 0x05, 0x9D, 0x8C, 0xC5, 0x34, 0x3F, 0x49, 0x12, 0x6B,
        0xD0, 0x46, 0x62, 0x25, 0x82, 0x32, 0x94, 0x3E, 0xFE, 0xB0, 0xA3, 0x59,
        0xCC, 0xCF, 0x93, 0xC5, 0x97, 0x24, 0x62, 0xD7, 0x8C, 0xAE, 0xAA, 0xD1,
        0xF2, 0x99, 0x87, 0xF8, 0x57, 0x0E, 0x47, 0x76, 0xDC, 0xA2, 0x52, 0xC0,
        0x4B, 0x52, 0x1D, 0x4D, 0x00, 0xE3, 0x31, 0x1B, 0x5C, 0x2F, 0x70, 0xC4,
        0x45, 0x08, 0x5E, 0x66, 0x47, 0x14, 0x82, 0x90, 0x3E, 0x0A, 0xEB, 0x65,
        0x94, 0x5A, 0x2E, 0x65, 0xC1, 0xD0, 0x64, 0xF4, 0x07, 0xE0, 0x41, 0x0A,
        0x57, 0x5B, 0xCC, 0xF6, 0x61, 0x37, 0xCE, 0xFF, 0xE1, 0x1F, 0x69, 0x50,
        0x97, 0x2B, 0xD0, 0x0A, 0x6B, 0x9F, 0xB2, 0xDC, 0x28, 0x4B, 0x4E, 0xF4,
        0xFF, 0x3F, 0xEC, 0x14, 0x1D, 0x89, 0x7C, 0x80, 0x09, 0x90, 0x79, 0x89,
        0x7A, 0x51, 0x15, 0xE8, 0x6D, 0x0E, 0xB9, 0xD3, 0xB9, 0xF8, 0xC6, 0xF4,
        0xAE, 0x0D, 0xD8, 0x33, 0xC0, 0xC7, 0x68, 0x75, 0x12, 0xA7, 0x93, 0xAD,
        0x3C, 0x76, 0x7B, 0x6F, 0xD6, 0x71, 0x2D, 0x06, 0x0F, 0x3D, 0x1F, 0x75,
        0x93, 0x37, 0x69, 0xE5, 0xB3, 0xB8, 0xD0, 0xE7, 0x8A, 0xAA, 0xAB, 0x53,
        0xF3, 0x32, 0x59, 0x47, 0x80, 0x60, 0xE6, 0x81, 0xA1, 0xE2, 0x8E, 0x3C,
        0x7D, 0xEE, 0x54, 0xD8, 0x6B, 0x84, 0x76, 0x4F, 0xBC, 0x2C, 0xFC, 0xFC,
        0x2B, 0x03, 0x43, 0x77, 0x48, 0x5D, 0x25, 0x7C, 0xFA, 0xB9, 0xB2, 0x0D,
        0xB4, 0x40, 0xBB, 0x07, 0xC2, 0xF4, 0x5E, 0xDF, 0x47, 0x8D, 0x60, 0xD6,
        0xD2, 0x60, 0xAB, 0x3D, 0x91, 0x9B, 0xBC, 0x68, 0x2A, 0x18, 0x25, 0xC3,
        0x5E, 0xD7, 0x12, 0x11, 0xF6, 0x14, 0x43, 0x61, 0x97, 0x8F, 0x39, 0x45,
        0x32, 0x13, 0xAF, 0x45, 0x73, 0x32, 0x77, 0x2B, 0xAE, 0xF5, 0xF8, 0xF0,
        0x5E, 0x87, 0x8A, 0xA1, 0x3D, 0x12, 0xC3, 0x89, 0xF4, 0xB7, 0x9D, 0xAB,
        0x79, 0x0D, 0xF0, 0xB6, 0xFE, 0x5A, 0xEA, 0xA0, 0xF4, 0xEF, 0xCC, 0x9C,
        0x9E, 0x95, 0x9B, 0xB0, 0xCF, 0x87, 0x4E, 0x23, 0xA2, 0x82, 0xC2, 0xC3,
        0x2B, 0xBB, 0x63, 0xF3, 0xF0, 0x5E, 0xEF, 0xCC, 0x20, 0xE0, 0x87, 0xCB,
        0x02, 0xD3, 0xCE, 0x2D, 0xBC, 0x6B, 0x28, 0xF6, 0xAB, 0xC4, 0xC8, 0x9B,
        0xC2, 0x55, 0x8E, 0x2C, 0x69, 0x47, 0x57, 0xFD, 0x80, 0xA8, 0xBB, 0x52,
        0xBC, 0xA2, 0x9D, 0x89, 0x13, 0x9F, 0x08, 0x5F, 0xE7, 0x33, 0x28, 0x31,
        0x8D, 0x63, 0x47, 0xDC, 0x57, 0x70, 0x04, 0x32, 0x53, 0x61, 0x60, 0x74,
        0xB6, 0x3B, 0x94, 0x53, 0xEA, 0x3B, 0x1D, 0xB5, 0x72, 0xA0, 0x5F, 0xE2,
        0x9D, 0x61, 0x06, 0x7A, 0x34, 0xFC, 0xB3, 0xD1, 0x34, 0x56, 0x33, 0x16,
        0x40, 0x35, 0x5C, 0x77, 0x05, 0xBF, 0x2F, 0xCE, 0x0F, 0x47, 0xCB, 0x93,
        0xBF, 0x58, 0xD2, 0x6E, 0x9A, 0xB8, 0x8E, 0x33, 0x51, 0xC7, 0x2A, 0x1E,
        0xE0, 0x80, 0xDA, 0x6A, 0xFE, 0x74, 0xBB, 0x8F, 0x99, 0xEC, 0xA8, 0xB6,
        0xC7, 0xF0, 0x66, 0xB4, 0xE7, 0x6C, 0x2A, 0x3A, 0x2A, 0x9B, 0x15, 0xB0,
        0x73, 0x33, 0x73, 0x80, 0x09, 0x14, 0xED, 0x77, 0xBB, 0xEC, 0x82, 0x7C,
        0xE8, 0x83, 0x74, 0x68, 0x53, 0xD0, 0x72, 0xFD, 0xC9, 0x52, 0x62, 0xF7,
        0x8C, 0xA6, 0x53, 0x7A, 0x7F, 0x6A, 0xDB, 0xE5, 0x7D, 0xA4, 0xB8, 0x7F,
        0x12, 0x6A, 0xAB, 0xDD, 0x9B, 0xF2, 0x08, 0x84, 0x25, 0x8C, 0x32, 0xA8,
        0x5A, 0x3C, 0x34, 0xA0, 0xC1, 0x32, 0x52, 0x27, 0xF2, 0xB6, 0x70, 0xB4,
        0xC2, 0xBD, 0x73, 0x69, 0xB1, 0x61, 0xFA, 0x5B, 0xFA, 0xB8, 0xEE, 0x0B,
        0x1B, 0xE6, 0x38, 0x41, 0x68, 0xAC, 0x84, 0x52, 0x33, 0x99, 0x9D, 0xEF,
        0x12, 0x45, 0x5C, 0xA8, 0xD2, 0x1F, 0xF4, 0xC8, 0x48, 0xE8, 0x77, 0xDE,
        0xCC, 0xEC, 0x8C, 0x36, 0x6C, 0xAE, 0xF1, 0x76, 0x0E, 0xFF, 0xB0, 0x96,
        0xA8, 0x7C, 0xE0, 0xB3, 0xD2, 0xC5, 0x6F, 0xAE, 0x31, 0x8D, 0x6A, 0xAD,
        0xBB, 0x23, 0x27, 0x58, 0x3B, 0x07, 0xBB, 0xE2, 0x5B, 0x72, 0xE9, 0x9E,
        0xCD, 0x71, 0x6E, 0x60, 0xF7, 0x33, 0x72, 0xCD, 0x99, 0xC5, 0x13, 0x17,
        0x6D, 0x02, 0xCE, 0xBE, 0x3A, 0x5B, 0x25, 0x83, 0x13, 0xEE, 0x5F, 0xE8,
        0xC4, 0xA4, 0x92, 0x40, 0x34, 0xFE, 0x42, 0xBF, 0xC5, 0xFB, 0xBF, 0x5B,
        0xF3, 0x1B, 0xCD, 0xD8, 0x23, 0xA5, 0x19, 0xD8, 0x6B, 0x68, 0x4D, 0x9E,
        0xB2, 0xEC, 0x82, 0x82, 0x63, 0x3A, 0x30, 0xF9, 0xE9, 0xD3, 0x97, 0xEF,
        0x52, 0x11, 0x86, 0x08, 0x69, 0xD0, 0x9D, 0x4A, 0xCB, 0x59, 0xFF, 0xE8,
        0x9F, 0xFB, 0x3C, 0xDF, 0xBF, 0xAC, 0x3E, 0x63, 0xA0, 0x78, 0xDB, 0x36,
        0x68, 0xFE, 0xB7, 0x90, 0x51, 0x75, 0x5C, 0xD4, 0xD7, 0x88, 0xDA, 0xA2,
        0x94, 0x5C, 0x27, 0x5B, 0x7B, 0x55, 0x8D, 0x87, 0x67, 0xD1, 0x5B, 0x2E,
        0xF0, 0x86, 0x1C, 0x6F, 0xC1, 0xC6, 0xFA, 0x7A, 0x25, 0x58, 0xB1, 0x8A,
        0xBB, 0x2C, 0x5B, 0x2C, 0xD8, 0xC9, 0x2C, 0x76, 0xF8, 0x46, 0xF6, 0xC6,
        0x72, 0x5D, 0xF8, 0xC6, 0xAD, 0xEE, 0x5F, 0xBB, 0x45, 0x6C, 0x8C, 0x17,
        0x14, 0x1B, 0x4F, 0x41, 0x65, 0x8E, 0x8B, 0x11, 0xBE, 0xD0, 0xBA, 0x97,
        0x7B, 0xCA, 0xBC, 0x1B, 0xC8, 0x9F, 0x64, 0x7C, 0x62, 0x4D, 0x7D, 0xE2,
        0x38, 0x21, 0xFB, 0x10, 0xF7, 0x94, 0x37, 0xE4, 0xE3, 0x24, 0xD4, 0x75,
        0x0A, 0x5F, 0x53, 0xAE, 0x36, 0xD7, 0x09, 0x07, 0x4D, 0xA7, 0x3E, 0x6A,
        0xB2, 0x5F, 0x2E, 0xC0, 0xCB, 0xF9, 0x2C, 0xA4, 0x0F, 0xC6, 0xE3, 0x2E,
        0xE5, 0xEA, 0x54, 0xE7, 0xCF, 0x22, 0x3C, 0xE1, 0xCB, 0xD8, 0xD9, 0xB6,
        0x29, 0xD1, 0xD9, 0x42, 0x78, 0xDB, 0x97, 0xF7, 0x5F, 0xD2, 0x35, 0xB8,
        0x9D, 0x12, 0x50, 0x6C, 0xB4, 0x6E, 0xFD, 0xC8, 0x00, 0x31, 0x38, 0xF2,
        0x8B, 0xE0, 0x2D, 0x23, 0x25, 0x6A, 0x6A, 0xA7, 0xAE, 0x52, 0x11, 0x00,
        0x72, 0x90, 0x36, 0x5B, 0xEB, 0xAE, 0x07, 0x6C, 0xD2, 0x91, 0x9E, 0xFB,
        0xB0, 0xB5, 0x87, 0x48, 0x21, 0xF7, 0x93, 0x19, 0x0F, 0x59, 0x77, 0xCF,
        0x91, 0xC2, 0xBB, 0xBC, 0xED, 0xD5, 0x96, 0xED, 0xCF, 0x2C, 0xDB, 0x86,
        0xA6, 0x6B, 0xEB, 0x6D, 0x22, 0xE4, 0xD6, 0x01, 0xCB, 0x19, 0x97, 0x5F,
        0xDF, 0xF1, 0x17, 0xCA, 0xC7, 0x99, 0x06, 0xEA, 0x79, 0x1B, 0x49, 0x58,
        0xFE, 0x91, 0x0B, 0x5D, 0xB5, 0xAE, 0xBA, 0xB7, 0xAE, 0x00, 0x9B, 0xBC,
        0x6E, 0x1A, 0xAA, 0xB4, 0x75, 0xD8, 0x94, 0x8C, 0xCF, 0x2B, 0x37, 0x76,
        0x0E, 0x3B, 0x91, 0xB5, 0x02, 0x19, 0x89, 0x67, 0x70, 0xF9, 0x3B, 0xB3,
        0x72, 0x77, 0xA9, 0xE9, 0x54, 0xDF, 0xE7, 0xCA, 0x81, 0x6C, 0x44, 0xE0,
        0xD1, 0x42, 0x67, 0x91, 0x79, 0xD1, 0x96, 0xF5, 0xBF, 0xB2, 0xD2, 0x1A,
        0x06, 0x83, 0xCD, 0x08, 0xA9, 0xD9, 0x0C, 0xF3, 0xCF, 0xEA, 0xF8, 0x1C,
        0xCE, 0x73, 0xCA, 0x65, 0x1C, 0xC7, 0x83, 0xE9, 0x7D, 0xB9, 0x2B, 0xA7,
        0x7D, 0x16, 0x5B, 0xB9, 0xAD, 0x48, 0x49, 0xC8, 0x36, 0x34, 0x10, 0x81,
        0xCA, 0xC6, 0xD3, 0x3B, 0x06, 0xE5, 0xC4, 0xB3, 0xF1, 0xBF, 0xBE, 0xFF,
        0xCD, 0x43, 0x64, 0x88, 0x93, 0x80, 0x12, 0x84, 0xB3, 0xF3, 0x5F, 0xF7,
        0xAD, 0x5D, 0x9A, 0xA1, 0xE1, 0x1C, 0x05, 0x42, 0x6D, 0x04, 0x36, 0xBF,
        0x79, 0xFA, 0x4C, 0xA2, 0xDC, 0x76, 0xB9, 0x00, 0x9E, 0x9B, 0xA8, 0x31,
        0x06, 0x2B, 0x9F, 0x66, 0xBA, 0x7C, 0xC0, 0x22, 0x72, 0xFD, 0xCA, 0x41,
        0x35, 0xE0, 0xCB, 0x44, 0x9B, 0x15, 0xF4, 0xC1, 0xCB, 0xCE, 0x92, 0x84,
        0x19, 0x72, 0x71, 0x56, 0xDB, 0xE6, 0x90, 0x29, 0xEA, 0x6C, 0xF1, 0x39,
        0xF7, 0x1D, 0x87, 0x3E, 0x69, 0x4E, 0x8E, 0x87, 0xB6, 0xEB, 0x73, 0x8C,
        0xB3, 0xCE, 0x79, 0xC6, 0x31, 0x21, 0xA2, 0x65, 0xF2, 0xEF, 0xC8, 0x42,
        0x04, 0x29, 0x7C, 0x66, 0xD0, 0xBC, 0x8D, 0xDE, 0xDA, 0xB9, 0xAD, 0xD9,
        0xE8, 0x09, 0xD2, 0x22, 0xAD, 0xDD, 0x8C, 0x3A, 0x2B, 0x3A, 0x16, 0x34,
        0x57, 0x6E, 0xA4, 0x92, 0x9B, 0x06, 0xD2, 0x25, 0xC3, 0xBE, 0x59, 0xD2,
        0x1A, 0xDA, 0x5D, 0x97, 0x60, 0xC6, 0x71, 0xEC, 0x38, 0xDE, 0xEA, 0x47
};

static const br_dilithium_private_key DLTHM = {
        (unsigned char *)DLTHM_RHO, sizeof DLTHM_RHO,
        (unsigned char *)DLTHM_KEY, sizeof DLTHM_KEY,
        (unsigned char *)DLTHM_TR, sizeof DLTHM_TR,
        (unsigned char *)DLTHM_S1, sizeof DLTHM_S1,
        (unsigned char *)DLTHM_S2, sizeof DLTHM_S2,
        (unsigned char *)DLTHM_T0, sizeof DLTHM_T0,
        4
};