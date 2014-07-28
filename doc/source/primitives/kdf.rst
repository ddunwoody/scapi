key Derivation Function
=======================

A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value with high entropy (but no other guarantee regarding its distribution).

.. contents::

The ``Key Derivation Function`` Interface:
------------------------------------------

.. java:method:: public SecretKey deriveKey(byte[] entropySource, int inOff, int inLen, int outLen)
   :outertype: KeyDerivationFunction

   Generates a new secret key from the given seed.

   :param entropySource: the secret key that is the seed for the key generation
   :param inOff: the offset within the entropySource to take the bytes from
   :param inLen: the length of the seed
   :param outLen: the required output key length
   :return: SecretKey the derivated key.

There is another variation of this function, that also takes into account an initial vector (iv):

.. java:method:: public SecretKey deriveKey(byte[] entropySource, int inOff, int inLen, int outLen, byte[] iv)
   :outertype: KeyDerivationFunction

   Generates a new secret key from the given seed and iv.

   :param entropySource: the secret key that is the seed for the key generation
   :param inOff: the offset within the entropySource to take the bytes from
   :param inLen: the length of the seed
   :param outLen: the required output key length
   :param iv: info for the key generation
   :return: SecretKey the derivated key.

Basic Usage
-----------

.. code-block:: java

    KeyDerivationFunction kdf = new HKDF(new BcHMAC());
    byte[] source = "...";
    int targetLen = 128;
    byte[] kdfed = kdf.deriveKey(source, 0, source.length, targetLen).getEncoded();

