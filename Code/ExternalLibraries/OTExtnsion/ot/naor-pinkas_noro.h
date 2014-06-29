/*
 * The Naor-Pinkas OT protocols that does not require a random oracle
 */
#pragma once
#ifndef NAOR_PINKAS_NORO_H
#define NAOR_PINKAS_NORO_H

#include "baseOT.h"
#include "double-exp.h"

class NaorPinkasNoRO : public BaseOT
{

	public:

	NaorPinkasNoRO(){};
	~NaorPinkasNoRO(){};
	
	NaorPinkasNoRO(int secparam, BYTE* seed, bool useecc){Init(secparam, seed, useecc);};

#ifdef OTEXT_USE_GMP
	// Sender and receiver method using GMP
	BOOL ReceiverIFC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL SenderIFC(int nSndVals, int nOTs, CSocket& sock,  BYTE* ret);
#endif
	
	// Sender and receiver method using Miracl
	BOOL ReceiverECC(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL SenderECC(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);

	
};
		


#endif
