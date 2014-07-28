Pseudorandom Function (PRF)
===========================

In cryptography, a **pseudorandom function family**, abbreviated **PRF**, is a collection of efficiently-computable functions which emulate a random function in the following way: no efficient algorithm can distinguish (with significant advantage) between a function chosen randomly from the PRF family and a random oracle (a function whose outputs are fixed completely at random).

.. contents::

The ``PseudorandomFunction`` Interface
--------------------------------------

The main function of this interface is ``computeBlock()``. We supply several versions for compute, with and without length. Since both PRP's and PRF's may have varying input/output length, for such algorithms the length should be supplied. We provide the version without the lengths and not just the versions with length of input and output, although it suffices, to avoid confusion and misuse from a basic user that only knows how to use block ciphers. A user that uses the block cipher TripleDES, may be confused by the “compute with length” functions since TripleDES has a pre-defined length and it cannot be changed.

Block Manipulation
~~~~~~~~~~~~~~~~~~

.. java:method:: public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException
    :outertype: PseudorandomFunction

    Computes the function using the secret key.
    The user supplies the input byte array and the offset from which to take the data from. 
    The user also supplies the output byte array as well as the offset. 
    The computeBlock function will put the output in the output array starting at the offset.
    This function is suitable for block ciphers where the input/output length is known in advance.
    
    :param inBytes: input bytes to compute
    :param inOff: input offset in the inBytes array
    :param outBytes: output bytes. The resulted bytes of compute
    :param outOff: output offset in the outBytes array to put the result from
    :throws IllegalBlockSizeException:

.. java:method:: public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException
    :outertype: PseudorandomFunction
	
    Computes the function using the secret key.
    This function is provided in the interface especially for the sub-family PrfVaryingIOLength, 
    which may have variable input and output length.
    If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advance and 
    the use may call the other computeBlock function where length is not require.
    
    :param inBytes: input bytes to compute
    :param inOff: input offset in the inBytes array
    :param inLen: the length of the input array
    :param outBytes: output bytes. The resulted bytes of compute
    :param outOff: output offset in the outBytes array to put the result from
    :param outLen: the length of the output array
    :throws IllegalBlockSizeException:

.. java:method:: public void computeBlock(byte[] inBytes, int inOffset, int inLen, byte[] outBytes, int outOffset) throws IllegalBlockSizeException
    :outertype: PseudorandomFunction
 
    Computes the function using the secret key.
 
    This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which the input length can be different for each computation. Hmac and Prf/Prp with variable input length are examples of such interfaces.
 
    :param inBytes: input bytes to compute
    :param inOffset: input offset in the inBytes array
    :param inLen: the length of the input array
    :param outBytes: output bytes. The resulted bytes of compute.
    :param outOffset: output offset in the outBytes array to put the result from
    :throws IllegalBlockSizeException:

.. java:method:: public int getBlockSize()
   :outertype: PseudorandomFunction

   :return: the input block size in bytes

Setting the Secret Key
~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException
   :outertype: PseudorandomFunction

   Generates a secret key to initialize this prf object.

   :param keyParams: algorithmParameterSpec contains the required parameters for the key generation
   :throws InvalidParameterSpecException:
   :return: the generated secret key

.. java:method:: public SecretKey generateKey(int keySize)
   :outertype: PseudorandomFunction

   Generates a secret key to initialize this prf object.

   :param keySize: is the required secret key size in bits
   :return: the generated secret key

.. java:method:: public boolean isKeySet()
   :outertype: PseudorandomFunction

   An object trying to use an instance of prf needs to check if it has already been initialized.

   :return: true if the object was initialized by calling the function setKey.

.. java:method:: public void setKey(SecretKey secretKey) throws InvalidKeyException
   :outertype: PseudorandomFunction

   Sets the secret key for this prf. The key can be changed at any time.

   :param secretKey: secret key
   :throws InvalidKeyException:

Basic Usage
-----------

.. code-block:: java

    //Create secretKey and in, in2, out byte arrays
    ...
    
    // initiate a PRF of type TripleDES using the PrfFactory
    PseudorandomFunction prf = PrfFactory.getInstance().getObject("TripleDES")
    
    //set the key
    prf.setKey(secretKey);
    
    //compute the function with input in and output out.
    prf.computeBlock(in, 0, out, 0);

Pseudorandom Function with Varying Input-Output Lengths
-------------------------------------------------------

A pseudorandom function with varying input/output lengths does not have pre-defined input and output lengths. The input and output length may be different for each compute function call. The length of the input as well as the output is determined upon user request. The class ``IteratedPrfVarying`` implements this functionality using an inner PRF that must implement the ``PrfVaryingInputLength`` interface. An example for such PRF is ``Hmac``.

How to use the Varying Input-Output Length PRF
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: java

    //Create secret key and in, out byte arrays
    ...

    //call the PrfFactory.
    PseudorandomFunction prf = PrfFactory.getInstance().getObject("IteratedPrfVarying(Hmac(SHA-1))");
    
    //set the key
    prf.setKey(secretKey);
    
    //compute the function with input in of size 10 and output out of size 20.
    prf.computeBlock(in, 0, 10, out, 0, 20);
