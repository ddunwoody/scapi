// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:


// NTLLibrary
#ifdef _DEBUG
#  pragma comment ( lib, "ntl_d" )
#  pragma comment ( lib, "gf2x_d" )

#else
#  pragma comment ( lib, "ntl" )
#  pragma comment ( lib, "gf2x" )
#endif


#include <windows.h>
#define NTL_NO_MIN_MAX



// TODO: reference additional headers your program requires here
