This program is a test program for pairings based proof of data possession.  (PPPAS)

It is an implementation of

C. Wang, S. Chow, Q. Wang, K. Ren, W. Lou "Privacy-Preserving Public Auditing for Secure Cloud Storage"

It's pretty much a proof of concept at this point.

## Dependencies

* gmp
* cryptopp
* pbc

On OS X:

```
brew install cryptopp pbc
```

# Getting it running

```
aclocal
autoconf
automake --add-missing
./configure
make check
```

That will run the one test case that I have written.

There isn't really a library at this point as this is a proof of concept.