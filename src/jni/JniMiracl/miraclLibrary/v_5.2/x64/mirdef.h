/*
 *   MIRACL compiler/hardware definitions - mirdef.h
 *   Copyright (c) 1988-2006 Shamus Software Ltd.
 */

#define MIRACL	64
#define MR_BIG_ENDIAN    /* This may need to be changed        */
#define mr_utype __int64
                            /* the underlying type is usually int *
                             * but see mrmuldv.any                */
#define mr_unsign64 unsigned long
#define mr_unsign32 unsigned int
                            /* 32 bit unsigned type               */
#define MR_IBITS      32    /* bits in int  */
#define MR_LBITS      64    /* bits in long */


#define MR_FLASH 52
#define MAXBASE ((mr_small)1<<(MIRACL-1))
//#define MAXBASE ((mr_small)1<<(mr_small)31)

#define MR_BITSINCHAR 8

#define MR_GENERIC_MT