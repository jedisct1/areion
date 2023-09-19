# Areion

This is an implementation of the [Areion](https://eprint.iacr.org/2023/794.pdf) permutation presented at CHES2023, as well as the Areion512-MD hash function.

Areion512-MD is a very fast hash function, even for small inputs.

~~Note that the output of this implementation doesn't match the test vectors of the paper. There are two bugs in the example code of the paper that was also used to produce the test vectors, which are thus incorrect.
The authors have been informed.~~
Following this, a new version of the paper has been published, with these issues fixed.