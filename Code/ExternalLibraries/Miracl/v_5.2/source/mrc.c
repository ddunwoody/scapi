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
  asm (
  "A1=A0=0;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*0]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*1]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*2]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*0] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*3]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*4]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*5]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%2+2*6]=R4;\n"
  "A0=A0>>16;\n"
  "R4=A0.W;\n"
  "W[%2+2*7]=R4;\n"
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
  asm (
  "A0=0;\n"
  "R4=W[%0+2*0] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*0]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%0+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*1]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%0+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=W[%0+2*1] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*2]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%0+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%0+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*3]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%0+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=W[%0+2*2] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*4]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%0+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*5]=R4;\n"
  "A0=A0>>16;\n"
  "R4=W[%0+2*3] (Z);\n"
  "A0+=R4.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%1+2*6]=R4;\n"
  "A0=A0>>16;\n"
  "R4=A0.W;\n"
  "W[%1+2*7]=R4;\n"
   :
   :"a"(a),"a"(c)
   :"R3","R4","A0","memory"
  );
    if (z->w[2*MR_COMBA-1]==0) mr_lzero(z); 
}                        
 
   
/* NOTE! t and z must be distinct! */

void comba_redc(_MIPD_ big t,big z)     
{  /* super comba Montgomery redc() function */                      
    mr_small carry,su;
#ifdef MR_ITANIUM
    register mr_small lo1,hi1,lo2,hi2,sumlo,sumhi,extra,ma,mb,sp,u;
#endif
#ifdef MR_WIN64
    mr_small lo,hi,sumlo,sumhi,extra,ma,mb,u; 
#endif
#ifdef MR_NOASM
    mr_large u;
#ifndef MR_SPECIAL
 #ifdef mr_qltype
    register mr_small sp;
    mr_large pp1;
    mr_vlarge sum;
 #else
    register mr_small sp,extra,s0,s1;
    mr_large pp1,pp2,sum;
 #endif
#endif
#endif

    unsigned int i;
    big w,modulus;
    mr_small *a,*b;
#ifndef MR_SPECIAL
    BOOL need_subtract;
    mr_small ndash;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif

#ifdef MR_SPECIAL


/* !!! Implement here a "special" fast method for modular reduction,
   for a particular modulus. Implemented here for 2^192-2^64-1       
   and 2^224-2^96+1 on a 32 bit processor.
   See for example "Software Implementation of the NIST Elliptic
   Curves Over Prime Fields", Brown et al., Report #36, 2000 available
   from www.cacr.math.uwaterloo.ca 

   The generated code can be manually optimised further.....
*/
    int overshoot;
    mr_small k[MR_COMBA],sn,tt,v;
#ifdef MR_PSEUDO_MERSENNE_142
    mr_small sh,sl;
#endif
    mr_small *c;

    modulus=mr_mip->modulus;     
    for (i=MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;
 /*      zero(z);   */
    z->len=MR_COMBA;

#ifdef MR_PSEUDO_MERSENNE_142

#if MIRACL==32

/* special code for 2^142-111 */

    sn=111;
    sh=t->w[4]>>14;
    t->w[4]&=0x3FFF;
    sl=t->w[5]>>14;
    t->w[5]<<=18; t->w[5]|=sh;
    sh=t->w[6]>>14;
    t->w[6]<<=18; t->w[6]|=sl;
    sl=t->w[7]>>14;
    t->w[7]<<=18; t->w[7]|=sh;
    sh=t->w[8]>>14;
    t->w[8]<<=18; t->w[8]|=sl;
    t->w[9]=sh;

    a=&(t->w[5]);
    b=k;
    c=z->w;

/*** PMULT ***/
  asm (
  "R1=0;\n"
  "R2=0;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*0]=R2;\n"
  "W[%2+2*0]=R3;\n"	
  "R3=W[%0+2*1] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*1]=R2;\n"
  "W[%2+2*1]=R3;\n"	
  "R3=W[%0+2*2] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*2]=R2;\n"
  "W[%2+2*2]=R3;\n"	
  "R3=W[%0+2*3] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*3]=R2;\n"
  "W[%2+2*3]=R3;\n"	
  "R3=%3.L*R1.L (FU);\n"
  "W[%1]=R3;\n"
  "R2=R3>>16;\n"
  "W[%1+2]=R2;\n"
   :
   :"a"(a),"a"(b),"a"(c),"d"(sn)
   :"R1","R2","R3","A0","A1","memory"
  );

    a=c;
    k[0]=(c[4]>>14)*111;
    c[4]&=0x3FFF;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    b=t->w;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    b=modulus->w;

    while (z->w[4]>>14)
    {
/*** DECREMENT ***/	
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    }

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

#endif

#if MIRACL==64

    sn=111;
    sh=t->w[2]>>14;
    t->w[2]&=0x3FFF;
    sl=t->w[3]>>14;
    t->w[3]<<=50; t->w[3]|=sh;
    sh=t->w[4]>>14;
    t->w[4]<<=50; t->w[4]|=sl;
    t->w[5]=sh;

    a=&(t->w[3]);
    b=k;
    c=z->w;

/*** PMULT ***/
  asm (
  "R1=0;\n"
  "R2=0;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*0]=R2;\n"
  "W[%2+2*0]=R3;\n"	
  "R3=W[%0+2*1] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*1]=R2;\n"
  "W[%2+2*1]=R3;\n"	
  "R3=W[%0+2*2] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*2]=R2;\n"
  "W[%2+2*2]=R3;\n"	
  "R3=W[%0+2*3] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*3]=R2;\n"
  "W[%2+2*3]=R3;\n"	
  "R3=%3.L*R1.L (FU);\n"
  "W[%1]=R3;\n"
  "R2=R3>>16;\n"
  "W[%1+2]=R2;\n"
   :
   :"a"(a),"a"(b),"a"(c),"d"(sn)
   :"R1","R2","R3","A0","A1","memory"
  );

    a=c;
    k[0]=(c[2]>>14)*111;
    c[2]&=0x3FFF;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    b=t->w;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    b=modulus->w;

    while (z->w[2]>>14)
    {
/*** DECREMENT ***/	
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    }

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);


#endif

#endif

#ifdef MR_PSEUDO_MERSENNE

    sn=(mr_small)0-modulus->w[0];  /* Modulus is 2^{MIRACL*MR_COMBA}-c. Here we calculate c */

/* .. where c MUST be a word sized ... */

    a=&(t->w[MR_COMBA]);
    b=k;
    c=z->w;

/*** PMULT ***/
  asm (
  "R1=0;\n"
  "R2=0;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*0]=R2;\n"
  "W[%2+2*0]=R3;\n"	
  "R3=W[%0+2*1] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*1]=R2;\n"
  "W[%2+2*1]=R3;\n"	
  "R3=W[%0+2*2] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*2]=R2;\n"
  "W[%2+2*2]=R3;\n"	
  "R3=W[%0+2*3] (Z);\n"
  "R3=%3.L*R3.L (FU);\n"
  "R3=R1+R3 (NS);\n"
  "R1=R3>>16;\n"
  "W[%1+2*3]=R2;\n"
  "W[%2+2*3]=R3;\n"	
  "R3=%3.L*R1.L (FU);\n"
  "W[%1]=R3;\n"
  "R2=R3>>16;\n"
  "W[%1+2]=R2;\n"
   :
   :"a"(a),"a"(b),"a"(c),"d"(sn)
   :"R1","R2","R3","A0","A1","memory"
  );

    a=c;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot=carry;
    b=t->w;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;
    
    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

#endif

#ifdef MR_GENERALIZED_MERSENNE

#if MIRACL==64

   #if MR_COMBA == 3
/* Special Code for 2^192-2^64-1 - assuming 64-bit processor */

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=a[3]; k[2]=0;

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;  
    a=c;  c=t->w;
    k[0]=0;k[1]=k[2]=c[4];

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;
    k[0]=k[1]=k[2]=c[5];

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;
    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

   #endif

   #if MR_COMBA == 2
/* Special code for 2^127-1 - for 64-bit processor */

  a=t->w;	
  k[0]=a[2]; k[1]=a[3];
  a=b=k;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );

  a=t->w;
  k[0]+=(a[1]>>63); k[1]|=(a[1]&0x8000000000000000);

  c=z->w;

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

  a=z->w;
  b=modulus->w;

  if (z->w[1]>=modulus->w[1])
  {
      if (mr_compare(z,modulus)>=0)
      {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
      }
  }
  if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

#endif


#if MIRACL==8

  #if MR_COMBA==32

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=k[2]=k[3]=k[4]=k[5]=k[6]=k[7]=k[8]=k[9]=k[10]=k[11]=0;
    k[12]=a[44]; k[13]=a[45]; k[14]=a[46]; k[15]=a[47];
    k[16]=a[48]; k[17]=a[49]; k[18]=a[50]; k[19]=a[51];
    k[20]=a[52]; k[21]=a[53]; k[22]=a[54]; k[23]=a[55]; 
    k[24]=a[56]; k[25]=a[57]; k[26]=a[58]; k[27]=a[59]; 
    k[28]=a[60]; k[29]=a[61]; k[30]=a[62]; k[31]=a[63]; 

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;
    a=c; c=t->w;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    
    k[0]=k[1]=k[2]=k[3]=k[4]=k[5]=k[6]=k[7]=k[8]=k[9]=k[10]=k[11]=0;
    k[12]=c[48]; k[13]=c[49]; k[14]=c[50]; k[15]=c[51];
    k[16]=c[52]; k[17]=c[53]; k[18]=c[54]; k[19]=c[55];
    k[20]=c[56]; k[21]=c[57]; k[22]=c[58]; k[23]=c[59]; 
    k[24]=c[60]; k[25]=c[61]; k[26]=c[62]; k[27]=c[63];
    k[28]=k[29]=k[30]=k[31]=0;


/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=c[32]; k[1]=c[33]; k[2]=c[34]; k[3]=c[35];
    k[4]=c[36]; k[5]=c[37]; k[6]=c[38]; k[7]=c[39];
    k[8]=c[40]; k[9]=c[41]; k[10]=c[42]; k[11]=c[43];
    k[12]=k[13]=k[14]=k[15]=k[16]=k[17]=k[18]=k[19]=k[20]=k[21]=k[22]=k[23]=0;
    k[24]=c[56]; k[25]=c[57]; k[26]=c[58]; k[27]=c[59]; 
    k[28]=c[60]; k[29]=c[61]; k[30]=c[62]; k[31]=c[63]; 


/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=c[36]; k[1]=c[37]; k[2]=c[38]; k[3]=c[39];
    k[4]=c[40]; k[5]=c[41]; k[6]=c[42]; k[7]=c[43];
    k[8]=c[44]; k[9]=c[45]; k[10]=c[46]; k[11]=c[47];
    k[12]=c[52]; k[13]=c[53]; k[14]=c[54]; k[15]=c[55];
    k[16]=c[56]; k[17]=c[57]; k[18]=c[58]; k[19]=c[59];
    k[20]=c[60]; k[21]=c[61]; k[22]=c[62]; k[23]=c[63]; 
    k[24]=c[52]; k[25]=c[53]; k[26]=c[54]; k[27]=c[55];
    k[28]=c[32]; k[29]=c[33]; k[30]=c[34]; k[31]=c[35];    

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=c[44]; k[1]=c[45]; k[2]=c[46]; k[3]=c[47];
    k[4]=c[48]; k[5]=c[49]; k[6]=c[50]; k[7]=c[51];
    k[8]=c[52]; k[9]=c[53]; k[10]=c[54]; k[11]=c[55];
    k[12]=k[13]=k[14]=k[15]=k[16]=k[17]=k[18]=k[19]=k[20]=k[21]=k[22]=k[23]=0;
    k[24]=c[32]; k[25]=c[33]; k[26]=c[34]; k[27]=c[35];
    k[28]=c[40]; k[29]=c[41]; k[30]=c[42]; k[31]=c[43];   


/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    k[0]=c[48]; k[1]=c[49]; k[2]=c[50]; k[3]=c[51];
    k[4]=c[52]; k[5]=c[53]; k[6]=c[54]; k[7]=c[55];
    k[8]=c[56]; k[9]=c[57]; k[10]=c[58]; k[11]=c[59];
    k[12]=c[60]; k[13]=c[61]; k[14]=c[62]; k[15]=c[63];
    k[16]=k[17]=k[18]=k[19]=k[20]=k[21]=k[22]=k[23]=0;
    k[24]=c[36]; k[25]=c[37]; k[26]=c[38]; k[27]=c[39];
    k[28]=c[44]; k[29]=c[45]; k[30]=c[46]; k[31]=c[47];    


/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    k[0]=c[52]; k[1]=c[53]; k[2]=c[54]; k[3]=c[55];
    k[4]=c[56]; k[5]=c[57]; k[6]=c[58]; k[7]=c[59];
    k[8]=c[60]; k[9]=c[61]; k[10]=c[62]; k[11]=c[63];
    k[12]=c[32]; k[13]=c[33]; k[14]=c[34]; k[15]=c[35];
    k[16]=c[36]; k[17]=c[37]; k[18]=c[38]; k[19]=c[39];
    k[20]=c[40]; k[21]=c[41]; k[22]=c[42]; k[23]=c[43]; 
    k[24]=k[25]=k[26]=k[27]=0;
    k[28]=c[48]; k[29]=c[49]; k[30]=c[50]; k[31]=c[51];  


/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    k[0]=c[56]; k[1]=c[57]; k[2]=c[58]; k[3]=c[59];
    k[4]=c[60]; k[5]=c[61]; k[6]=c[62]; k[7]=c[63];
    k[8]=k[9]=k[10]=k[11]=0;
    k[12]=c[36]; k[13]=c[37]; k[14]=c[38]; k[15]=c[39];
    k[16]=c[40]; k[17]=c[41]; k[18]=c[42]; k[19]=c[43];
    k[20]=c[44]; k[21]=c[45]; k[22]=c[46]; k[23]=c[47]; 
    k[24]=k[25]=k[26]=k[27]=0;
    k[28]=c[52]; k[29]=c[53]; k[30]=c[54]; k[31]=c[55];  


/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    b=modulus->w;
    while (overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot+=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

  #if MR_COMBA == 16

/* Special code for 2^127-1 - for 8-bit processor */

  a=t->w;	
  k[0]=a[16]; k[1]=a[17]; k[2]=a[18]; k[3]=a[19];
  k[4]=a[20]; k[5]=a[21]; k[6]=a[22]; k[7]=a[23];
  k[8]=a[24]; k[9]=a[25]; k[10]=a[26]; k[11]=a[27];
  k[12]=a[28]; k[13]=a[29]; k[14]=a[30]; k[15]=a[31];

  a=b=k;

/*** DOUBLEIT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );

  a=t->w;
  k[0]+=(a[15]>>7); k[15]|=(a[15]&0x80);

  c=z->w;

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

  a=z->w;
  b=modulus->w;

/* if MSB is 1, try and deal with it here */

  tt=(mr_small)(z->w[15]>>M1);
  v=z->w[0]+tt;
  if (v>=z->w[0])
  {
      z->w[15]-=(mr_small)(tt<<M1);
      z->w[0]=v;
  }

/* This is probably not going to happen now... */

  if (z->w[15]>=modulus->w[15])
  {
      if (mr_compare(z,modulus)>=0)
      {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
      }
  }
  if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

   #if MR_COMBA==20

   /* 2^160-2^112+2^64+1 */

/* faster way - keep a[20] to a[39] in registers r2-r21. 
*/

   a=t->w; b=k; c=z->w;

   k[0]=k[8]=a[38]; k[2]=k[4]=k[6]=k[10]=k[12]=0; k[14]=a[20]; k[16]=a[22]; k[18]=a[24];
   k[1]=k[9]=a[39]; k[3]=k[5]=k[7]=k[11]=k[13]=0; k[15]=a[21]; k[17]=a[23]; k[19]=a[25];

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;
    a=c; c=t->w;
    k[0]=k[2]=k[4]=k[6]=0; k[8]=k[14]=k[16]=c[34]; k[10]=c[36]; k[12]=c[24];  k[18]=0;
    k[1]=k[3]=k[5]=k[7]=0; k[9]=k[15]=k[17]=c[35]; k[11]=c[37]; k[13]=c[25];  k[19]=0;

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[4]=c[24]; k[6]=k[12]=k[14]=c[32]; k[0]=k[8]=c[20]; k[2]=k[10]=c[22]; k[16]=k[18]=c[36];
    k[5]=c[25]; k[7]=k[13]=k[15]=c[33]; k[1]=k[9]=c[21]; k[3]=k[11]=c[23]; k[17]=k[19]=c[37];

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[0]=k[6]=k[8]=c[26]; k[4]=k[10]=k[12]=c[30]; k[2]=k[14]=k[16]=k[18]=0;
    k[1]=k[7]=k[9]=c[27]; k[5]=k[11]=k[13]=c[31]; k[3]=k[15]=k[17]=k[19]=0;

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[2]=k[8]=k[10]=c[28]; k[0]=k[4]=k[6]=k[16]=0; k[12]=k[14]=k[18]=c[38];
    k[3]=k[9]=k[11]=c[29]; k[1]=k[5]=k[7]=k[17]=0; k[13]=k[15]=k[19]=c[39];   
   
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot+=carry;
    }

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);     

   #endif
#endif

#if MIRACL==16
   #if MR_COMBA==10

 /* 2^160-2^112+2^64+1 */ 

   a=t->w; b=k; c=z->w;
   k[0]=k[4]=a[19]; k[1]=k[2]=k[3]=k[5]=k[6]=0; k[7]=a[10]; k[8]=a[11]; k[9]=a[12]; 

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;
    a=c; c=t->w;
    k[0]=k[1]=k[2]=k[3]=0; k[4]=k[7]=k[8]=c[17]; k[5]=c[18]; k[6]=c[12];  k[9]=0;

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[2]=c[12]; k[3]=k[6]=k[7]=c[16]; k[0]=k[4]=c[10]; k[1]=k[5]=c[11]; k[8]=k[9]=c[18];

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[0]=k[3]=k[4]=c[13]; k[2]=k[5]=k[6]=c[15]; k[1]=k[7]=k[8]=k[9]=0;

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[1]=k[4]=k[5]=c[14]; k[0]=k[2]=k[3]=k[8]=0; k[6]=k[7]=k[9]=c[19];
    
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot+=carry;
    }

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);
   #endif
#endif

#if MIRACL==32

#if MR_COMBA == 8
#ifdef MR_NOFULLWIDTH

/* Modulus is 2^255-19 - Experimental - not tested! */

w->w=&(t->w[10]);
w->len=9;
premult(_MIPP_ w,608,w);
incr(_MIPP_ w,19*(t->w[9]>>21),w);
t->w[9]&=(1<<21)-1;
t->len++;
z->len=10;
for (i=0;i<10;i++) z->w[i]=t->w[i];
comba_sub(z,w,z);


#endif
#endif

  #if MR_COMBA == 4

/* Special code for 2^127-1 - for 32-bit processor */

  a=t->w;	
  k[0]=a[4]; k[1]=a[5]; k[2]=a[6]; k[3]=a[7];
  a=b=k;

/*** DOUBLEIT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );

  a=t->w;
  k[0]+=(a[3]>>31); k[3]|=(a[3]&0x80000000);

  c=z->w;

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

  a=z->w;
  b=modulus->w;

  if (z->w[3]>=modulus->w[3])
  {
      if (mr_compare(z,modulus)>=0)
      {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
      }
  }
  if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

  #if MR_COMBA == 6

/* Special Code for 2^192-2^64-1 - assuming 32-bit processor */

    a=t->w; b=k; c=z->w;
    k[0]=k[2]=a[6]; k[1]=k[3]=a[7]; k[4]=k[5]=0; 
    
/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;  
    a=c;  c=t->w;
    k[0]=k[1]=0; k[2]=k[4]=c[8]; k[3]=k[5]=c[9];

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;
    k[0]=k[2]=k[4]=c[10]; k[1]=k[3]=k[5]=c[11];
                       
/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;
    b=modulus->w;
    while(overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

  #if MR_COMBA == 7
/* Special Code for 2^224-2^96+1 - assuming 32-bit processor */

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=k[2]=0; k[3]=a[7]; k[4]=a[8]; k[5]=a[9]; k[6]=a[10];

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;
    a=c; c=t->w;
    k[0]=k[1]=k[2]=k[6]=0; k[3]=c[11]; k[4]=c[12]; k[5]=c[13];

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;
    k[0]=c[7]; k[1]=c[8]; k[2]=c[9]; k[3]=c[10]; k[4]=c[11]; k[5]=c[12]; k[6]=c[13];
    
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    k[0]=c[11]; k[1]=c[12]; k[2]=c[13]; k[3]=k[4]=k[5]=k[6]=0;

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;
    b=modulus->w;
    while (overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot+=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

  #endif

  #if MR_COMBA == 8
    #ifndef MR_NOFULLWIDTH

    a=t->w; b=k; c=z->w;
    k[0]=k[1]=k[2]=0; k[3]=a[11]; k[4]=a[12]; k[5]=a[13]; k[6]=a[14]; k[7]=a[15];

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    overshoot=carry;
    a=c; c=t->w;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=k[1]=k[2]=0; k[3]=c[12]; k[4]=c[13]; k[5]=c[14]; k[6]=c[15]; k[7]=0;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=c[8]; k[1]=c[9]; k[2]=c[10]; k[3]=k[4]=k[5]=0; k[6]=c[14]; k[7]=c[15];

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=c[9]; k[1]=c[10]; k[2]=c[11]; k[3]=c[13]; k[4]=c[14]; k[5]=c[15]; k[6]=c[13]; k[7]=c[8];

/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot+=carry;

    k[0]=c[11]; k[1]=c[12]; k[2]=c[13]; k[3]=k[4]=k[5]=0; k[6]=c[8]; k[7]=c[10];

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    k[0]=c[12]; k[1]=c[13]; k[2]=c[14]; k[3]=c[15]; k[4]=k[5]=0; k[6]=c[9]; k[7]=c[11];

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    k[0]=c[13]; k[1]=c[14]; k[2]=c[15]; k[3]=c[8]; k[4]=c[9]; k[5]=c[10]; k[6]=0; k[7]=c[12];

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    k[0]=c[14]; k[1]=c[15]; k[2]=0; k[3]=c[9]; k[4]=c[10]; k[5]=c[11]; k[6]=0; k[7]=c[13];

/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    overshoot-=carry;

    b=modulus->w;
    while (overshoot>0)
    {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot-=carry;
    }
    while (overshoot<0)
    {
/*** INCREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        overshoot+=carry;
    }
    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);

    #endif
  #endif

  #if MR_COMBA == 17

/* Special Code for 2^521-1 - assuming 32-bit processor */

/* split t into 521-bit halves, low half in a, high half in b */

    a=t->w; b=k; c=z->w;

    for (i=0;i<=16;i++)
        b[i]=(a[i+16]>>9)|(a[i+17]<<23);

    b[16]|=(-(a[16]>>9)<<9); /* clever stuff! Set top part of b[16] to minus  *
                              * top part of a[16]. When added they cancel out */

/*** ADDITION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
                             /* ignore carry=1 */
    a=z->w;                   
    b=modulus->w;

    if (z->w[MR_COMBA-1]>=modulus->w[MR_COMBA-1])
    {
        if (mr_compare(z,modulus)>=0)
        {
/*** DECREMENT ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
        }
    }
    if (z->w[MR_COMBA-1]==0) mr_lzero(z);
  #endif
  #endif
  #endif
#else
    modulus=mr_mip->modulus;  
    ndash=mr_mip->ndash;
    w=mr_mip->w0;
    if (t!=w) copy(t,w);       
    w->len=2*MR_COMBA+1;
    a=w->w; b=modulus->w;

/*** REDC ***/      /* reduces a mod b */
  asm (
  "A1=A0=0;\n"
  "R4=W[%0] (Z);\n"
  "A0.L=R4.L;\n"
  "R4=A0.W;\n"
  "R3=R4.L*%2.L (FU);\n"
  "W[%0+2*0]=R3;\n"
  "R4=W[%1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*0+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "R3=R4.L*%2.L (FU);\n"
  "W[%0+2*1]=R3;\n"
  "R4=W[%1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*1+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "R3=R4.L*%2.L (FU);\n"
  "W[%0+2*2]=R3;\n"
  "R4=W[%1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*2+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R3=W[%0+2*0] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "R3=R4.L*%2.L (FU);\n"
  "W[%0+2*3]=R3;\n"
  "R4=W[%1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*3+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R3=W[%0+2*1] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*1] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%0+2*4]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*4+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R3=W[%0+2*2] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*2] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%0+2*5]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*5+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R3=W[%0+2*3] (Z);\n"
  "R4=W[%1+2*3] (Z);\n"
  "A0+=R3.L*R4.L (FU);\n"
  "R4=A0.W;\n"
  "W[%0+2*6]=R4;\n"
  "A0=A0>>16;\n"
  "R3=W[%0+2*6+2] (Z);\n"
  "A1.L=R3.L ;\n"
  "A0+=A1 ;\n"
  "R4=A0.W;\n"
  "W[%0+2*7]=R4;\n"
  "A0=A0>>16;\n"
  "R4=A0.W;\n"
  "W[%0+2*7+2]=R4;\n" 
   :
   :"a"(a),"a"(b),"d"(ndash)
   :"R3","R4","A0","A1","memory"
  );

    for (i=MR_COMBA;i<(int)(z->len&MR_OBITS);i++) z->w[i]=0;
   
    z->len=MR_COMBA;
    for (i=0;i<MR_COMBA;i++) z->w[i]=w->w[i+MR_COMBA];

    need_subtract=FALSE;

    if (w->w[MR_COMBA+MR_COMBA]!=0)
    {
        need_subtract=TRUE;
    }
    else 
    {
        if (z->w[MR_COMBA-1]!=0)
        {
            if (z->w[MR_COMBA-1]>modulus->w[MR_COMBA-1]) need_subtract=TRUE;
            else
            {
                if (z->w[MR_COMBA-1]==modulus->w[MR_COMBA-1])
                {
                    if (mr_compare(z,modulus)>=0) need_subtract=TRUE;
                }
            }
        }
        else mr_lzero(z);
    }

    if (need_subtract)
    {
        a=z->w; b=modulus->w;
/*** DECREMENT ***/    
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
	z->len=MR_COMBA;
        if (z->w[MR_COMBA-1]==0) mr_lzero(z);
    }

#endif
} 

#ifdef MR_SPECIAL
#ifdef MR_GENERALIZED_MERSENNE
#if MIRACL*MR_COMBA == 128
#define MR_FAST_MOD_ADD 2
#endif
#endif
#endif

#ifdef MR_SPECIAL
#ifdef MR_PSEUDO_MERSENNE
#define MR_FAST_MOD_ADD 1
#define MR_OP(c) ( ((mr_utype)((c)<<M1)) >>M1)
#endif
#endif

void comba_modadd(_MIPD_ big x,big y,big w)
{ /* fast modular addition */
    unsigned int i;
    big modulus;
    BOOL dodec;
    mr_small *a,*b,*c;
    mr_small carry,su; 
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,mb,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

#ifdef MR_FAST_MOD_ADD
    mr_small sc,t,v;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (w!=x && w!=y) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    
    a=x->w; b=y->w; c=w->w;
/*** ADDITION ***/        /* add a and b, result in c */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    w->len=MR_COMBA;

#ifdef MR_FAST_MOD_ADD

#if MR_FAST_MOD_ADD == 1

    sc=(mr_small)0-modulus->w[0];  /* Modulus is 2^{MIRACL*MR_COMBA}-c. Here we calculate c */
    t=MR_OP(carry)&sc;
    v=w->w[0]+t;
    if (v>=w->w[0])
    {
	w->w[0]=v;
	carry=0;
    }

#endif

#if MR_FAST_MOD_ADD == 2

    t=(mr_small)(w->w[MR_COMBA-1]>>M1);
    v=w->w[0]+t;
    if (v>=w->w[0])
    {
        w->w[MR_COMBA-1]-=(mr_small)(t<<M1);
	w->w[0]=v;
	carry=0;
    }

#endif

#endif

/* if sum is greater than modulus a decrement will be required */

    dodec=FALSE;
    if (carry) dodec=TRUE;  /* possible misprediction here */
    else
    {
        if (w->w[MR_COMBA-1]>modulus->w[MR_COMBA-1]) dodec=TRUE; /* possible misprediction here */
	else
	{
            if (w->w[MR_COMBA-1]==modulus->w[MR_COMBA-1]) /* this will be very rare, so easily predicted */
	    { /* trying to avoid calling this slow function */
	        if (mr_compare(w,modulus)>=0) dodec=TRUE; /* do full comparison */
	    }
        }
    }

    if (dodec)  /* prediction here correlated to earlier predictions, so should predict nicely */
    {
        a=w->w; b=modulus->w;
/*** DECREMENT ***/        /* decrement b from a */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    }
    
    if (w->w[MR_COMBA-1]==0) mr_lzero(w);   

}

void comba_add(big x,big y,big w)
{ /* fast addition */
    unsigned int i;
    mr_small *a,*b,*c;
    mr_small carry,su; 
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,mb,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif
    
    if (w!=x && w!=y) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    
    a=x->w; b=y->w; c=w->w;
/*** ADDITION ***/        /* add a and b, result in c */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

    w->len=MR_COMBA;
    if (w->w[MR_COMBA-1]==0) mr_lzero(w);   
}

void comba_modsub(_MIPD_ big x,big y,big w)
{ /* fast modular subtraction */
    unsigned int i;
    big modulus;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif
#ifdef MR_FAST_MOD_ADD
    mr_small sc,t,v;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (x!=w && y!=w) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;   
        /* zero(w); */
    }

    a=x->w; b=y->w; c=w->w;
/*** SUBTRACTION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

#ifdef MR_FAST_MOD_ADD

#if MR_FAST_MOD_ADD == 1

    sc=(mr_small)0-modulus->w[0];  /* Modulus is 2^{MIRACL*MR_COMBA}-c. Here we calculate c */
    t=MR_OP(carry)&sc;
    v=w->w[0]-t;
    if (v<=w->w[0])
    {
	w->w[0]=v;
	carry=0;
    }

#endif

#if MR_FAST_MOD_ADD == 2

    t=(w->w[MR_COMBA-1]>>M1);
    v=w->w[0]-t;
    if (v<=w->w[0])
    {
        w->w[MR_COMBA-1]-=(t<<M1);
	w->w[0]=v;
	carry=0;
    }

#endif

#endif

    if (carry)
    {
        a=w->w; b=modulus->w; 
/*** INCREMENT ***/        /* add a and b, result in c */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    
    }
    w->len=MR_COMBA;
    if (w->w[MR_COMBA-1]==0) mr_lzero(w); 
}

void comba_sub(big x,big y,big w)
{ /* fast subtraction */
    unsigned int i;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

    if (x!=w && y!=w) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;   
        /* zero(w); */
    }

    a=x->w; b=y->w; c=w->w;
/*** SUBTRACTION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

    w->len=MR_COMBA;
    if (w->w[MR_COMBA-1]==0) mr_lzero(w); 
}

#ifndef MR_NO_LAZY_REDUCTION

void comba_double_modadd(_MIPD_ big x,big y,big w)
{ /* fast modular addition */
    unsigned int i;
    big modulus;
    BOOL dodec;
    mr_small *a,*b,*c;
    mr_small carry,su; 
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif    
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->pR;
    if (w!=x && w!=y) 
    {
        for (i=2*MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    
    a=x->w; b=y->w; c=w->w;
/*** ADDITION2 ***/        /* add a and b, result in c */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*4] (Z);\n"
  "R4=W[%2+2*4] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*4]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*5] (Z);\n"
  "R4=W[%2+2*5] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*5]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*6] (Z);\n"
  "R4=W[%2+2*6] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*6]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*7] (Z);\n"
  "R4=W[%2+2*7] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*7]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    w->len=2*MR_COMBA;

/* if sum is greater than modulus a decrement will be required */

    dodec=FALSE;
    if (carry) dodec=TRUE;  /* possible misprediction here */
    else
    {
        if (w->w[2*MR_COMBA-1]>modulus->w[2*MR_COMBA-1]) dodec=TRUE; /* possible misprediction here */
	else
	{
            if (w->w[2*MR_COMBA-1]==modulus->w[2*MR_COMBA-1]) /* this will be very rare, so easily predicted */
	    {
	        if (mr_compare(w,modulus)>=0) dodec=TRUE; /* do full comparison */
	    }
	}
    }

    if (dodec)  /* prediction here correlated to earlier predictions, so should predict nicely */
    {
         a=&(w->w[MR_COMBA]); b=&(modulus->w[MR_COMBA]);
/*** DECREMENT ***/        /* decrement b from a */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    }
    if (w->w[2*MR_COMBA-1]==0) mr_lzero(w);   

}

void comba_double_add(big x,big y,big w)
{ /* fast modular addition */
    unsigned int i;
    mr_small *a,*b,*c;
    mr_small carry,su; 
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif    
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

    if (w!=x && w!=y) 
    {
        for (i=2*MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    
    a=x->w; b=y->w; c=w->w;
/*** ADDITION2 ***/        /* add a and b, result in c */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*4] (Z);\n"
  "R4=W[%2+2*4] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*4]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*5] (Z);\n"
  "R4=W[%2+2*5] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*5]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*6] (Z);\n"
  "R4=W[%2+2*6] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*6]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*7] (Z);\n"
  "R4=W[%2+2*7] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%3+2*7]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );
    w->len=2*MR_COMBA;

    if (w->w[2*MR_COMBA-1]==0) mr_lzero(w);   

}

void comba_double_modsub(_MIPD_ big x,big y,big w)
{ /* fast modular subtraction */
    unsigned int i;
    big modulus;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (x!=w && y!=w) 
    {
        for (i=2*MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;   
        /* zero(w); */
    }

    a=x->w; b=y->w; c=w->w;
/*** SUBTRACTION2 ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*4] (Z);\n"
  "R4=W[%2+2*4] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*4]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*5] (Z);\n"
  "R4=W[%2+2*5] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*5]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*6] (Z);\n"
  "R4=W[%2+2*6] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*6]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*7] (Z);\n"
  "R4=W[%2+2*7] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*7]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

    if (carry)
    {
        a=&(w->w[MR_COMBA]); b=modulus->w; 
/*** INCREMENT ***/        /* add a and b, result in c */
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R4+R3;\n"
  "W[%1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*1]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*2]=R3;\n"
  "%0=R3>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R4+R3;\n"
  "R3=%0+R3;\n"
  "W[%1+2*3]=R3;\n"
  "%0=R3>>16;\n"
  :"=d"(carry)
  :"a"(a),"a"(b)
  :"R3","R4","memory"
  );
    
    }
    w->len=2*MR_COMBA;
    if (w->w[2*MR_COMBA-1]==0) mr_lzero(w); 
}

void comba_double_sub(big x,big y,big w)
{ /* fast modular subtraction */
    unsigned int i;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

    if (x!=w && y!=w) 
    {
        for (i=2*MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;   
        /* zero(w); */
    }

    a=x->w; b=y->w; c=w->w;
/*** SUBTRACTION2 ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*4] (Z);\n"
  "R4=W[%2+2*4] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*4]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*5] (Z);\n"
  "R4=W[%2+2*5] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*5]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*6] (Z);\n"
  "R4=W[%2+2*6] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*6]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*7] (Z);\n"
  "R4=W[%2+2*7] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*7]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

    w->len=2*MR_COMBA;
    if (w->w[2*MR_COMBA-1]==0) mr_lzero(w); 
}

#endif

void comba_negate(_MIPD_ big x,big w)
{ /* fast modular subtraction */
    unsigned int i;
    big modulus;
    mr_small *a,*b,*c;
    mr_small carry,su;  
#ifdef MR_WIN64
    mr_small ma,mb,u;
#endif
#ifdef MR_ITANIUM
    mr_small ma,u;
#endif
#ifdef MR_NOASM
    mr_large u;
#endif

#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
    modulus=mr_mip->modulus;
    if (w!=x) 
    {
        for (i=MR_COMBA;i<(w->len&MR_OBITS);i++) w->w[i]=0;
        /* zero(w); */
    }
    a=modulus->w; b=x->w; c=w->w;

/*** SUBTRACTION ***/
  asm (
  "R3=W[%1] (Z);\n"
  "R4=W[%2] (Z);\n"
  "R3=R3-R4;\n"
  "W[%3]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*1] (Z);\n"
  "R4=W[%2+2*1] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*1]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*2] (Z);\n"
  "R4=W[%2+2*2] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*2]=R3;\n"
  "%0=R3>>>16;\n"
  "R3=W[%1+2*3] (Z);\n"
  "R4=W[%2+2*3] (Z);\n"
  "R3=R3-R4;\n"
  "R3=%0+R3;\n"
  "W[%3+2*3]=R3;\n"
  "%0=R3>>>16;\n"
  "%0=-%0;\n"
  :"=d"(carry)
  :"a"(a),"a"(b),"a"(c)
  :"R3","R4","memory"
  );

    w->len=MR_COMBA;
    if (w->w[MR_COMBA-1]==0) mr_lzero(w); 
}

#endif
