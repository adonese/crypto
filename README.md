# Crypto package

Includes various encryption algorithms for payment applications in Sudan. Currently, the library supports:

- PIN encryption (DES for POS) in Python
- iPIN encryption (RSA) in Go (go language)

Soon we will be adding:
- JS (iPIN)
- Java (PIN, iPIN)
- WASM (IPIN)

## Notes TODO #3

This project uses different languages, but we tried to make clear instructions per each directory. 


## TODO #1s

- Add more testing
- Implement web interface

## Directory listing

We follow a simple directory structure, since we have PIN and IPIN encryption, it goes like this:

- directories have *.language_extension to indicate the language being used. E.g., ipin.js directory means this holds ipin encryption in javascript. And so on

We currently have the following implementations and languages, authors are listed as well:

- pin (@adonese)
- ipin.js (fakhrisati)
- pin.java (@wadjaafar)
- cli (@adonese)
- ipin.java (@wadjaafar)