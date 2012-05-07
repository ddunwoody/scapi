/*
 *   MIRACL Comba's method for ultimate speed modular multiplication
 *   mrcomba.tpl 
 *
 *   See "Exponentiation Cryptosystems on the IBM PC", IBM Systems
 *   Journal Vol. 29 No. 4 1990. Comba's method has been extended to 
 *   implement Montgomery reduction. 
 *
 *   Here the inner loops of the basic multiplication, squaring and 
 *   Montgomery's redc() functions are completely unravelled, and 
 *   reorganised for maximum possible speed. 
 *
 *   This approach is recommended for maximum speed where parameters
 *   are fixed and compute resources are constrained. The processor must 
 *   support an unsigned multiply instruction, and should have a carry flag.
 *
 *   This file is a template. To fill in the gaps and create mrcomba.c, 
 *   you must run the mex.c program to insert the C or assembly language 
 *   macros from the appropriate .mcs file. For use with C MR_NOASM must
 *   be defined in mirdef.h
 *
 *   This method would appear to be particularly useful for implementing 
 *   fast Elliptic Curve Cryptosystems over GF(p) and fast 1024-bit RSA
 *   decryption.
 *
 *   The #define MR_COMBA in mirdef.h determines the FIXED size of 
 *   modulus to be used. This *must* be determined at compile time. 
 *
 *   Note that this module can generate a *lot* of code for large values 
 *   of MR_COMBA. This should have a maximum value of 8-16. Any larger 
 *   that and you should define MR_KCM instead - see mrkcm.tpl
 *
 *   Note that on some processors it is *VITAL* that arrays be aligned on 
 *   4-byte boundaries
 *
 *  **** This code does not like -fomit-frame-pointer using GCC  ***********
 *
 *   Copyright (c) 1988-2001 Shamus Software Ltd.
 */

#include "miracl.h"    

#ifdef MR_COMBA

  
/* NOTE! z must be distinct from x and y */

void comba_mult(big x,big y,big z) 
{ /* comba multiplier */
    int i;
    mr_small *a,*b,*c;
   
#ifdef MR_WIN64
    mr_small lo,hi,sumlo,sumhi,extra; 
#endif
#ifdef MR_ITANIUM
    register mr_small lo1,hi1,lo2,hi2,sumlo,sumhi,extra,ma,mb;
#else
#ifdef MR_NOASM 
 #ifdef mr_qltype
    mr_large pp1;
    mr_vlarge sum;
 #else
    register mr_small extra,s0,s1;
    mr_large pp1,pp2,sum;
 #endif
#endif
#endif
   
    for (i=2*MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;
  
    z->len=2*MR_COMBA;
    a=x->w; b=y->w; c=z->w;
/*** MULTIPLY ***/      /* multiply a by b, result in c */
  ASM (
  "A0=0;\n"
  "R3=W[%0+0] (Z);\n"
  "R4=W[%1+0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+0]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+0] (Z);\n"
  "R4=W[%1+2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2] (Z);\n"
  "R4=W[%1+0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+0] (Z);\n"
  "R4=W[%1+4] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2] (Z);\n"
  "R4=W[%1+2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+4] (Z);\n"
  "R4=W[%1+0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+4]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+0] (Z);\n"
  "R4=W[%1+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2] (Z);\n"
  "R4=W[%1+4] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+4] (Z);\n"
  "R4=W[%1+2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+6] (Z);\n"
  "R4=W[%1+0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+6]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2] (Z);\n"
  "R4=W[%1+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+4] (Z);\n"
  "R4=W[%1+4] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+6] (Z);\n"
  "R4=W[%1+2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+8]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+4] (Z);\n"
  "R4=W[%1+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+6] (Z);\n"
  "R4=W[%1+4] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+10]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+6] (Z);\n"
  "R4=W[%1+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+12]=R4;\n"
  "A0=A0>>16;\n"
  "R4=A0.W;\n"
  "W[%2+14]=R4;\n"
   :
   :"a"(a),"a"(b),"a"(c)
   :"R3","R4","A0","A1","memory"
  );
    if (z->w[2*MR_COMBA-1]==0) mr_lzero(z);
}   
 
/* NOTE! z and x must be distinct */

void comba_square(big x,big z)  
{ /* super comba squarer */
    int i;
    mr_small *a,*c;
  
#ifdef MR_WIN64
    mr_small lo,hi,sumlo,sumhi,extra,cy; 
#endif
#ifdef MR_ITANIUM
    register mr_small lo1,hi1,lo2,hi2,sumlo,sumhi,extra,ma,mb;
#endif
#ifdef MR_NOASM
 #ifdef mr_qltype
    mr_large pp1;
    mr_vlarge sum;
 #else
    register mr_small extra,s0,s1;
    mr_large pp1,pp2,sum;
 #endif
#endif

    for (i=2*MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;  
 
    z->len=2*MR_COMBA;
    a=x->w; c=z->w;
/*** SQUARE ***/    /* squares a, result in b */
  ASM (
  "A0=0;\n"
  "R4=W[%0+0] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+0]=R4;\n"
  "A0=A0>>16;\n"

  "R3=W[%0+0] (Z);\n"
  "R4=W[%0+2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2]=R4;\n"
  "A0=A0>>16;\n"

  "R3=W[%0+0] (Z);\n"
  "R4=W[%0+4] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=W[%0+2] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+4]=R4;\n"
  "A0=A0>>16;\n"

  "R3=W[%0+0] (Z);\n"
  "R4=W[%0+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2] (Z);\n"
  "R4=W[%0+4] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+6]=R4;\n"
  "A0=A0>>16;\n"

  "R3=W[%0+2] (Z);\n"
  "R4=W[%0+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=W[%0+4] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+8]=R4;\n"
  "A0=A0>>16;\n"

  "R3=W[%0+4] (Z);\n"
  "R4=W[%0+6] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+10]=R4;\n"
  "A0=A0>>16;\n"

  "R4=W[%0+6] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+12]=R4;\n"
  "A0=A0>>16;\n"

  "R4=A0.W;\n"
  "W[%1+14]=R4;\n"
   :
   :"a"(a),"a"(c)
   :"R3","R4","A0","memory"
  );
    if (z->w[2*MR_COMBA-1]==0) mr_lzero(z); 
}                        
   

#endif