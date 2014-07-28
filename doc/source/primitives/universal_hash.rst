Universal Hash
==============

A **universal hash function** is a family of hash functions with the property that a randomly chosen hash function (from the family) yields very few collisions, with good probability. More importantly in a cryptographic context, universal hash functions have important properties, like good randomness extraction and pairwise independence. Many universal families are known (for hashing integers, vectors, strings), and their evaluation is often very efficient.

The notions of universal hashing and cryptographic hash are distinct, and should not be confused (it is unfortunate that they have a similar name). We therefore completely separate the two implementations so that cryptographic hash functions cannot be confused with universal hash functions.

The output length of universal hash function is fixed for any given instantiation. The input is fixed (maybe for a certain instantiation) for some implementations and may be varying for other implementations. Since the input can be either fixed or varying we supply a compute function with input length as an argument for the varying version. The function ``getInputLength()`` plays a slightly different role for each version.

.. contents::

The ``UniversalHash`` interface
-------------------------------

.. java:method:: public void setKey(SecretKey secretKey)

    Sets the secret key for this UH. The key can be changed at any time. 

    :param secretKey: secret key
    :throws: InvalidKeyException

.. java:method:: public boolean isKeySet()

    An object trying to use an instance of UH needs to check if it has already been initialized.

    :return: ``true`` if the object was initialized by calling the function ``setKey``.

.. java:method:: public int getInputSize()

    This function has multiple roles depending on the concrete hash function.
    
    If the concrete class can get a varying input lengths then there are 2 possible answers:
    
    1. The maximum size of the input if there is some kind of an upper bound on the input size
    (for example in the EvaluationHashFunction there is a limit on the input size due to security reasons).
    Thus, this function returns this bound even though the actual size can be any number between zero and that limit.
    
    2. If there is no limit on the input size, this function returns 0.
    
    Otherwise, if the concrete class can get a fixed length, 
    this function returns a constant size that may be determined either in the init 
    for some implementations or hardcoded for other implementations.
    
    :return: the input size of this hash function

.. java:method:: public int getOutputSize()

    :return: the output size of this hash function

.. java:method:: public SecretKey generateKey(AlgorithmParameterSpec keyParams)

    Generates a secret key to initialize this UH object.

    :param keyParams: contains the required parameters for the key generation
    :throws: InvalidParameterSpecException
    :return: the generated secret key

.. java:method:: public SecretKey generateKey(int keySize)

    Generates a secret key to initialize this UH object.

    :param keySize: is the required secret key size in bits
    :return: the generated secret key

.. java:method:: public void compute(byte[] in, int inOffset, int inLen, byte[] out, int outOffset)

    Computes the hash function on the in byte array and put the result in the output byte array.
    
    :param in: input byte array
    :param inOffset: the offset within the input byte array
    :param inLen: the number of bytes to take after the offset
    :param out: output byte array
    :param outOffset: the offset within the output byte array
    :throws: IllegalBlockSizeException if the input length is greater than the upper limit

Example of Usage
----------------

.. code-block:: java

    // create an input array in and an output array out
    ...
    
    // initiates an EvaluationHashFunction object using the UniversalHashFactory
    UniversalHash uh = UniversalHashFactory.getInstance().getObject("ScapiEvaluationHash");
    
    // calls the compute() function in the UniversalHash interface
    uh.compute(in, 0, in.length, out, 0);

Supported Hash Types
--------------------

In this section we present possible keys to the ``UniversalHashFactory``.
Currently, there is only one supported implementation of ``UniversalHash``.

===================   ==============================================================
Key                   Class
===================   ==============================================================
ScapiEvaluationHash   edu.biu.scapi.primitives.universalHash.EvaluationHashFunction
===================   ==============================================================
    
