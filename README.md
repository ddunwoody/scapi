SCAPI - The Secure Computation API
==================================

SCAPI is an open-source Java library for implementing secure two-party and multiparty computation protocols (SCAPI stands for the "Secure Computation API"). It provides a reliable, efficient, and highly flexible cryptographic infrastructure. SCAPI is comprised of three layers:

1. Low-level cryptographic functions: these are functions that are basic building blocks for cryptographic constructions (e.g., pseudorandom functions, pseudorandom generators, discrete logarithm groups, hash functions and more belong to this layer).
2. Non-interactive mid-level cryptographic functions: these are non-interactive functions that can be applications within themselves in addition to being tools (e.g., encryption and signature schemes belong to this layer).
3. Interactive cryptographic protocols: these are interactive protocols involving two or more parties; typically, the protocols in this layer are popular building blocks like commitment schemes, zero knowledge proofs and oblivious transfer.

More information about SCAPI appears in this [paper](http://crypto.biu.ac.il/scapi/scapi.pdf), and on the [Documentation page](http://crypto.biu.ac.il/documentation-scapi.php).