# Tyche
Experiments in randomness from user space

## Introduction
I was asked to...

```
"Build a clone of $ cat /dev/random in the scripting language of your choice, generating your own entropy."
```

A short and sweet request. However, it has some subtleties...

* The most problematic issue is "generating your own entropy." The
  assumption here is that the mechanisms /dev/random uses within the
  kernel are supposed to be relatively secure. Yet there is considerable
  debate as to how secure various implementations really are.

* Attempting to generate entropy from user space (as opposed to kernel
  space) is problematic.  Any information retrieved from the outside
  world via system calls can be "spoofed" by an attack with
  appropriate access to the system (e.g. via ptrace(2)). This includes
  reading from devices (which, of course, means reading from
  /dev/random is itself at risk), retrieving system time stamps, and
  so on. So the challenge is how to effectively generate entropy from
  user code without depending on system calls to communicate with the
  kernel. Ultimately, this is all moot since outputting the random
  data from our program can be spoofed. For this exercise, we will
  assume a secure and properly permissioned system so that we can
  trust system calls.

* There has been a lot of controversy about /dev/random, which will
  block until the system estimates that sufficient entropy has been
  gathered. More recently, improved efficiency in the Linux kernel has
  let to a problem with /dev/random blocking much longer or even
  forever. This has inspired some interesting work on additional
  sources of entropy (e.g. jitter from CPU speculative execution - see
  http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html.

* Different Unix-style operating systems (e.g. Linux, MacOS, FreeBSD)
  and even different versions of those use different pseudo random
  number generator (PRNG) algorithms. For example, MacOS uses a Yarrow
  algorithm and FreeBSD uses a Fortuna algorithm. Since /dev/random
  is supposed to provide a cryptographically secure random number
  generator we should do something similar to achieve forward and
  backward secrecy.

## Approach

For a scripting language, I am chosing Python 3.7. There is debate as
to whether Python should be considered a scripting language but I
don't want to do this in bash. ;-)

I have decided to implement a basic version of the Fortuna Pseudo
Random Number Generator (PRNG) as devised by Bruce Schneir and Niels
Ferguson as a replacement for the Yarrow PRNG.

I've called my algorithm Tyche, the Greed goddess of fortune. Fortuna
is the Roman goddess of Fortune.

This algorithm requires a cryptographic hash as well as a good
cryptographic cipher that uses non-linear mixing functions to achieve
forward secrecy. We will use SHA256 for the hash and AES for the block
cipher.

The Python standard library provides SHA256 and we will use the
cryptography package from https://pypi.org/project/cryptography/ for
our AES implementation.

I've implemented everything in a single Python file, tyche_prng.py,
for simplicity.

### Wishful Thinking

Of course, if we didn't have to generate our own entropy, we could
simply use the secrets package. As per the documentation...

```
The secrets module provides access to the most secure source of randomness that your operating system provides.
```

Then we could just solve the assignment with something like (see
secrets_random.py for a complete program):

```python
while True:
    random_byte_string = secrets.token_bytes(64)
    os.write(1, random_byte_string)
```

### Entropy Sources

The more entropy sources the better. If a source of entropy is compromised
safety is still provided by mixing entropy from additional uncompromised
sources.

The code has been structured to allow addding an arbitrary number of
entropy sources. In the time allowed I have added two entropy sources
so far:

* Code execution jitter - I have a chunk of code that is likely to
  vary in execution time with each run due to its tendency to touch
  multiple pages of memory and some conditional execution that *might*
  cause the CPU to behave differently due to speculative
  execution. The timing does change each time around (though not
  enough for industrial use).

* Process operating statistics - I query the system for various stats
  about the current process.

It is easy to add others. The code makes it clear where to add more
sources of entropy. I didn't have time to implement more.

I'll add more detail here later but I'm out of time for now.

## Running the code

You need Python 3 and the cryptography package which can be installed
in your environment with...

```bash
pip install cryptography
```

Then you should be able to run the program like...

python3 tyche_prng.py | od -x | more

~chuck