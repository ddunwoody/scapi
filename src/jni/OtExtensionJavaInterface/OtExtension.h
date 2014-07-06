#ifndef _MPC_H_
#define _MPC_H_

#include <OtExtension/util/typedefs.h>
#include <OtExtension/util/socket.h>
#include <OtExtension/ot/naor-pinkas.h>
#include <OtExtension/ot/asharov-lindell.h>
#include <OtExtension/ot/ot-extension.h>
#include <OtExtension/util/cbitvector.h>
#include <OtExtension/ot/xormasking.h>

#include <vector>
#include <time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;

static const char* m_nSeed = "437398417012387813714564100";

USHORT		m_nPort = 7766;
const char* m_nAddr ;// = "localhost";

BOOL Init();
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

OTExtensionSender* InitOTSender(const char* address, int port);
OTExtensionReceiver* InitOTReceiver(const char* address, int port);

BOOL PrecomputeNaorPinkasSender();
BOOL PrecomputeNaorPinkasReceiver();
BOOL ObliviouslyReceive(OTExtensionReceiver* receiver, CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version);
BOOL ObliviouslySend(OTExtensionSender* sender, CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version, CBitVector& delta);

// Network Communication
vector<CSocket> m_vSockets;
int m_nPID; // thread id
int m_nSecParam; 
bool m_bUseECC;
int m_nBitLength;
int m_nMod;
MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
BaseOT* bot;

CBitVector U; 
BYTE *vKeySeeds;
BYTE *vKeySeedMtx;

int m_nNumOTThreads;

// SHA PRG
BYTE				m_aSeed[SHA1_BYTES];
int			m_nCounter;
double			rndgentime;


#endif //_MPC_H_
