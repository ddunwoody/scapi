Cryptographic Hash
==================

A **cryptographic hash** function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string, the (cryptographic) hash value. There are two main levels of security that we will consider here: 

*  **target collision resistance:** meaning that given :math:`x` it is hard to find :math:`y` such that :math:`H(y)=H(x)`.

*  **collision resistance:** meaning that it is hard to find any :math:`x` and :math:`y` such that :math:`H(x)=H(y)`.

.. note:: We do not include **preimage resistance** since cryptographically this is just a `one-way function`_.

.. contents::

The ``CryptographicHash`` interface
-----------------------------------

The user may request to pass partial data to the hash and only after some iterations to obtain the hash of all the data. This is done by calling the function ``update()``. After the user is done updating the data it can call the ``hashFinal()`` to obtain the hash output.

.. java:method:: void update(byte[] in, int inOffset, int inLen)

   Adds the byte array to the existing msg to hash.

   :param in: input byte array
   :param inOffset: the offset within the byte array
   :param inLen: the length. The number of bytes to take after the offset

.. java:method:: void hashFinal(byte[] out, int outOffset)

   Completes the hash computation.

   :param out: the output in byte array
   :param outOffset: the offset which to put the result bytes from

Usage
-----

The best way to use CryptographicHash is via the `CryptographicHashFactory`_ factory class.

.. code-block:: java

    //create an input array in and an output array out 
    ...
    
    //call the CryptographicHashFactory.
    CryptographicHash hash = CryptographicHashFactory.getInstance().getObject("SHA-1");

    //call the update function in the Hash interface.
    hash.update(in, 0, in.length);

    //get the result of hashing the updated input.
    hash.hashFinal(out, 0);

.. _`CryptographicHashFactory`:

Supported Hash Types
--------------------

In this section we present possible keys to the ``CryptographicHashFactory``.

Default keys: (point to the Crypto++ implementation)

==================   ======================================================
Key                  Class
==================   ======================================================
SHA-1                CryptoPP
SHA-224              CryptoPP
SHA-256              CryptoPP
SHA-384              CryptoPP
SHA-512              CryptoPP
==================   ======================================================

The BouncyCastle implementation:

==================   ======================================================
Key                  Class
==================   ======================================================
BCSHA-1              edu.biu.scapi.primitives.hash.bc.BcSHA1
BCSHA-224            edu.biu.scapi.primitives.hash.bc.BcSHA224
BCSHA-256            edu.biu.scapi.primitives.hash.bc.BcSHA256
BCSHA-384            edu.biu.scapi.primitives.hash.bc.BcSHA384
BCSHA-512            edu.biu.scapi.primitives.hash.bc.BcSHA512
==================   ======================================================

The Crypto++ implementation (explicit keys):

==================   ======================================================
Key                  Class
==================   ======================================================
CryptoPPSHA-1        edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1
CryptoPPSHA-224      edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA224
CryptoPPSHA-256      edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA256
CryptoPPSHA-384      edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA384
CryptoPPSHA-512      edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA512
==================   ======================================================

The OpenSSL implementation:

==================   ======================================================
Key                  Class
==================   ======================================================
OpenSSLSHA-1         edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA1
OpenSSLSHA-224       edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA224
OpenSSLSHA-256       edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA256
OpenSSLSHA-384       edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA384
OpenSSLSHA-512       edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA512
==================   ======================================================

.. _`one-way function`: 
