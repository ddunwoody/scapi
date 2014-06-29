/*
 * MaskingFunction.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */
#pragma once
#ifndef MASKINGFUNCTION_H
#define MASKINGFUNCTION_H

#include "../util/cbitvector.h"
#include "../util/typedefs.h"

class MaskingFunction
{

public:
	MaskingFunction(){};
	~MaskingFunction(){};

	virtual void	Mask(int progress, int len, CBitVector* values, CBitVector& snd_buf, CBitVector& delta)  = 0;
	virtual void 	UnMask(int progress, int len, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf) = 0;

protected:


};


#endif /* MASKINGFUNCTION_H_ */
