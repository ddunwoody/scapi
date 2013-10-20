#include "stdafx.h"
#include "OtExtension.h"
#include "OtExtensionSemiHonestReceiver.h"
#include "OtExtensionSemiHonestSender.h"
#include "jni.h"



//#define OTTiming

BOOL Init()
{
	// Random numbers
	SHA_CTX sha;
	OTEXT_HASH_INIT(&sha);
	OTEXT_HASH_UPDATE(&sha, (BYTE*) &m_nPID, sizeof(m_nPID));
	OTEXT_HASH_UPDATE(&sha, (BYTE*) m_nSeed, sizeof(m_nSeed));
	OTEXT_HASH_FINAL(&sha, m_aSeed);

	m_nCounter = 0;

	//Number of threads that will be used in OT extension
	m_nNumOTThreads = 1;

	m_vSockets.resize(m_nNumOTThreads);

	bot = new NaorPinkas(m_nSecParam, m_aSeed, m_bUseECC);

	return TRUE;
}

BOOL Cleanup()
{
	for(int i = 0; i < m_nNumOTThreads; i++)
	{
		m_vSockets[i].Close();
	}
	return true;
}


BOOL Connect()
{
	BOOL bFail = FALSE;
	LONG lTO = CONNECT_TIMEO_MILISEC;

#ifndef BATCH
	cout << "Connecting to party "<< !m_nPID << ": " << m_nAddr << ", " << m_nPort << endl;
#endif
	for(int k = m_nNumOTThreads-1; k >= 0 ; k--)
	{
		for( int i=0; i<RETRY_CONNECT; i++ )
		{
			if( !m_vSockets[k].Socket() ) 
			{	
				printf("Socket failure: ");
				goto connect_failure; 
			}
			
			if( m_vSockets[k].Connect( m_nAddr, m_nPort, lTO))
			{
				// send pid when connected
				m_vSockets[k].Send( &k, sizeof(int) );
		#ifndef BATCH
				cout << " (" << !m_nPID << ") (" << k << ") connected" << endl;
		#endif
				if(k == 0) 
				{
					//cout << "connected" << endl;
					return TRUE;
				}
				else
				{
					break;
				}
				SleepMiliSec(10);
				m_vSockets[k].Close();
			}
			SleepMiliSec(20);
			if(i+1 == RETRY_CONNECT)
				goto server_not_available;
		}
	}
server_not_available:
	printf("Server not available: ");
connect_failure:
	cout << " (" << !m_nPID << ") connection failed" << endl;
	return FALSE;
}



BOOL Listen()
{
#ifndef BATCH
	cout << "Listening: " << m_nAddr << ":" << m_nPort << ", with size: " << m_nNumOTThreads << endl;
#endif
	if( !m_vSockets[0].Socket() ) 
	{
		goto listen_failure;
	}
	if( !m_vSockets[0].Bind(m_nPort, m_nAddr) )
		goto listen_failure;
	if( !m_vSockets[0].Listen() )
		goto listen_failure;

	for( int i = 0; i<m_nNumOTThreads; i++ ) //twice the actual number, due to double sockets for OT
	{
		CSocket sock;
		//cout << "New round! " << endl;
		if( !m_vSockets[0].Accept(sock) )
		{
			cerr << "Error in accept" << endl;
			goto listen_failure;
		}
					
		UINT threadID;
		sock.Receive(&threadID, sizeof(int));

		if( threadID >= m_nNumOTThreads )
		{
			sock.Close();
			i--;
			continue;
		}

	#ifndef BATCH
		cout <<  " (" << m_nPID <<") (" << threadID << ") connection accepted" << endl;
	#endif
		// locate the socket appropriately
		m_vSockets[threadID].AttachFrom(sock);
		sock.Detach();
	}

#ifndef BATCH
	cout << "Listening finished"  << endl;
#endif
	return TRUE;

listen_failure:
	cout << "Listen failed" << endl;
	return FALSE;
}




OTExtensionSender* InitOTSender(const char* address, int port)
{
	int nSndVals = 2;
#ifdef OTTiming
	timeval np_begin, np_end;
#endif
	m_nPort = (USHORT) port;
	m_nAddr = address;
	vKeySeeds = (BYTE*) malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS);
	
	//Initialize values
	Init();
	
	//Server listen
	Listen();
	
#ifdef OTTiming
	gettimeofday(&np_begin, NULL);
#endif	

	PrecomputeNaorPinkasSender();

#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif	

	return new OTExtensionSender (nSndVals, m_vSockets.data(), U, vKeySeeds);
}

OTExtensionReceiver* InitOTReceiver(const char* address, int port)
{
	int nSndVals = 2;
	timeval np_begin, np_end;
	m_nPort = (USHORT) port;
	m_nAddr = address;
	//vKeySeedMtx = (AES_KEY*) malloc(sizeof(AES_KEY)*NUM_EXECS_NAOR_PINKAS * nSndVals);
	vKeySeedMtx = (BYTE*) malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS * nSndVals);
	//Initialize values
	Init();
	
	//Client connect
	Connect();
	
#ifdef OTTiming
	gettimeofday(&np_begin, NULL);
#endif

	PrecomputeNaorPinkasReceiver();
	
#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif	

	return new OTExtensionReceiver(nSndVals, m_vSockets.data(), vKeySeedMtx, m_aSeed);
}

BOOL PrecomputeNaorPinkasSender()
{

	int nSndVals = 2;
	BYTE* pBuf = new BYTE[NUM_EXECS_NAOR_PINKAS * SHA1_BYTES]; 
	int log_nVals = (int) ceil(log((double)nSndVals)/log(2.0)), cnt = 0;
	
	U.Create(NUM_EXECS_NAOR_PINKAS*log_nVals, m_aSeed, cnt);
	
	bot->Receiver(nSndVals, NUM_EXECS_NAOR_PINKAS, U, m_vSockets[0], pBuf);
	
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for(int i=0; i<NUM_EXECS_NAOR_PINKAS; i++ ) //80 HF calls for the Naor Pinkas protocol
	{
		memcpy(vKeySeeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx+=SHA1_BYTES;
	} 
 	delete [] pBuf;	

 	return true;
}

BOOL PrecomputeNaorPinkasReceiver()
{
	int nSndVals = 2;
	
	// Execute NP receiver routine and obtain the key 
	BYTE* pBuf = new BYTE[SHA1_BYTES * NUM_EXECS_NAOR_PINKAS * nSndVals];

	//=================================================	
	// N-P sender: send: C0 (=g^r), C1, C2, C3 
	bot->Sender(nSndVals, NUM_EXECS_NAOR_PINKAS, m_vSockets[0], pBuf);
	
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for(int i=0; i<NUM_EXECS_NAOR_PINKAS * nSndVals; i++ )
	{
		memcpy(vKeySeedMtx + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx += SHA1_BYTES;
	}
	
	delete [] pBuf;	

	return true;
}


BOOL ObliviouslySend(OTExtensionSender* sender, CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version, CBitVector& delta)
{
	bool success = FALSE;
	int nSndVals = 2; //Perform 1-out-of-2 OT
#ifdef OTTiming
	timeval ot_begin, ot_end;
#endif

	
#ifdef OTTiming
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT sender routine 	
	success = sender->send(numOTs, bitlength, X1, X2, delta, version, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	printf("%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
	return success;
}

BOOL ObliviouslyReceive(OTExtensionReceiver* receiver, CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version)
{
	bool success = FALSE;

#ifdef OTTiming
	timeval ot_begin, ot_end;
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT receiver routine 	
	success = receiver->receive(numOTs, bitlength, choices, ret, version, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	printf("%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
	
	return success;
}



//-----------------------------------------------------------------------------------------------------//
//-------- JNI functions that will be called by the java application that will load this dll ----------//
//-----------------------------------------------------------------------------------------------------//

/*
 * Function initOtReceiver : This function initializes the receiver object and creates the connection with the sender
 * 
 * param ipAddress : The ip address of the receiver computer for connection
 * param port : The port to be used for sending/receiving data over the network
 * returns : A pointer to the receiver object that was created and later be used to run the protcol
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otExtensionSemiHonest_OTSemiHonestExtensionReceiver_initOtReceiver
  (JNIEnv *env, jobject, jstring ipAddress, jint port){


	//Use elliptic curve cryptography in the base-OTs
	m_bUseECC = true;
	//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
	m_nSecParam = 163;
	  //get the string from java
	const char* adrr = env->GetStringUTFChars( ipAddress, NULL );
	return (jlong) InitOTReceiver(adrr, port);

}


/*
 * Function runOtAsReceiver : This function runs the ot extension as the sender.
 * 
 * param sigma : The input array that holds all the receiver inputs for each ot in a one dimensional array.
 * param bitLength : The length of each element
 * param output : An empty array that will be filled with the result of the ot extension in one dimensional array. That is, 
				  The relevant i'th element x1/x2 will be placed in the position bitLength*sizeof(BYTE).
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otExtensionSemiHonest_OTSemiHonestExtensionReceiver_runOtAsReceiver
  (JNIEnv *env, jobject, jlong receiver, jbyteArray sigma, jint numOfOts, jint bitLength, jbyteArray output){

	  BYTE version = G_OT;

	  CBitVector choices, response;
	//Create the bitvector choices as a bitvector with numOTs entries
	//for(bitlength = 1; bitlength < 66; bitlength++)
	//{
	m_fMaskFct = new XORMasking(bitLength);
	choices.Create(numOfOts, m_aSeed, m_nCounter);

	jbyte *sigmaArr = env->GetByteArrayElements(sigma, 0);
	jbyte *out = env->GetByteArrayElements(output, 0);


	//Pre-generate the respose vector for the results
	response.Create(numOfOts, bitLength);

	//copy the sigma values received from java
	for(int i=0; i<numOfOts;i++){

		choices.SetBit(i, sigmaArr[i]);
	}

		//run the ot extension as the receiver
	ObliviouslyReceive((OTExtensionReceiver*) receiver , choices, response, numOfOts, bitLength, version);

		//prepare the out array
	for(int i = 0; i < numOfOts*bitLength/8; i++)
	{
		//copy each byte result to out
		out[i] = response.GetByte(i);
	}

	//make sure to release the memory created in c++. The JVM will not release it automatically.
	env->ReleaseByteArrayElements(sigma,sigmaArr,0);
	env->ReleaseByteArrayElements(output,out,0);
}


/*
 * Function initOtSender : This function initializes the sender object and creates the connection with the receiver
 * 
 * param ipAddress : The ip address of the sender computer for connection
 * param port : The port to be used for sending/receiving data over the network
 * returns : A pointer to the receiver object that was created and later be used to run the protcol
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otExtensionSemiHonest_OTSemiHonestExtensionSender_initOtSender
  (JNIEnv *env, jobject,jstring ipAddress, jint port){

	//Use elliptic curve cryptography in the base-OTs
	m_bUseECC = true;
	//The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
	m_nSecParam = 163;
	  //get the string from java
	const char* adrr = env->GetStringUTFChars( ipAddress, NULL );
	return (jlong) InitOTSender(adrr, port);

}

/*
 * Function runOtAsSender : This function runs the ot extension as the sender.
 * 
 * param x1 : The input array that holds all the x1,i for each ot in a one dimensional array one element after the other
 * param x2 : The input array that holds all the x2,i for each ot in a one dimensional array one element after the other
 * param bitLength : The length of each element
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otExtensionSemiHonest_OTSemiHonestExtensionSender_runOtAsSender
  (JNIEnv *env, jobject, jlong sender, jbyteArray x1, jbyteArray x2, jint numOfOts, jint bitLength){

	  cout << "Playing as role:Sender " << endl;
	//The masking function with which the values that are sent in the last communication step are processed
	//Choose OT extension version: G_OT, C_OT or R_OT
	BYTE version = G_OT;

	jbyte *x1Arr = env->GetByteArrayElements(x1, 0);
	jbyte *x2Arr= env->GetByteArrayElements(x2, 0);


	  CBitVector delta, X1, X2;
		//creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
		//for(bitlength = 1; bitlength < 66; bitlength++)
		//{
		m_fMaskFct = new XORMasking(bitLength);

		delta.Create(numOfOts, bitLength, m_aSeed, m_nCounter);
		//Create X1 and X2 as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
		X1.Create(numOfOts, bitLength);
		X1.Reset();
		X2.Create(numOfOts, bitLength);
		X2.Reset();

		for(int i = 0; i < numOfOts*bitLength/8; i++)
		{
			X1.SetByte(i, x1Arr[i]);
			X2.SetByte(i, x2Arr[i]);			
		}

		//run the ot extension as the sender
		cout << "Sender performing " << numOfOts << " OT extensions on " << bitLength << " bit elements" << endl;
		ObliviouslySend((OTExtensionSender*) sender, X1, X2, numOfOts, bitLength, version, delta);

		//make sure to release the memory created in c++. The JVM will not release it automatically.
		env->ReleaseByteArrayElements(x1,x1Arr,0);
		env->ReleaseByteArrayElements(x2,x2Arr,0);
}
