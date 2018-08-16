---
title: Hybrid ECDHE-SIDH Key Exchange for TLS
abbrev: ECDHE-SIDH Key Exchange
docname: draft-kiefer-tls-ecdhe-sidh-latest
category: exp

ipr: trust200902
area: IRTF
keyword: Internet-Draft

stand_alone: yes
pi:

author:
 -  ins: F. Kiefer
    name: Franziskus Kiefer
    organization: Mozilla
    email: franziskuskiefer@gmail.com
 -  ins: K. Kwiatkowski
    name: Krzysztof Kwiatkowski
    organization: Cloudflare
    email: kris@cloudflare.com

informative:
  eSIDH:
     title: "Efficient algorithms for supersingular isogeny Diffie-Hellman"
     author:
       - ins: C. Costello
       - ins: P. Longa
       - ins: M. Naehrig
     date: 2016
     seriesinfo: IACR-CRYPTO-2016
     target: https://eprint.iacr.org/2016/413.pdf
  ISOSEC:
      title: "On the security of supersingular isogeny cryptosystems"
      date: 2016
      author:
        - ins: S. Galbraith
        - ins: C. Petit
        - ins: B. Shani
        - ins: Y. Bo Ti
      seriesinfo: IACR-CRYPTO-2016
      target: https://eprint.iacr.org/2016/859.pdf
  KLM15:
      title: "Failure is not an Option: Standardization Issues for Post-Quantum Key Agreement"
      date: 2015
      author:
        - ins: D. Kirkwood
        - ins: B. Lackey
        - ins: J. McVey
        - ins: M. Motley
        - ins: J. Solinas
        - ins: D. Tuller
      seriesinfo: Workshop on Cybersecurity in a Post Quantum World, 2015
  URBJAO:
      title: "SoK: The Problem Landscape of SIDH"
      date: 2018
      author:
        - ins: D. Urbanik
        - ins: D. Jao
      seriesinfo: IACR-CRYPTO-2018
      target: https://eprint.iacr.org/2018/336.pdf
  RNSL:
      title: "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms"
      date: 2017
      author:
        - ins: M. Roetteler
        - ins: M. Naehrig
        - ins: K. Svore
        - ins: K. Lauter
      seriesinfo: arXiv
      target: https://arxiv.org/pdf/1706.06752.pdf
normative:
  RFC7748:
  RFC5869:
  SIDH:
     title: "Towards quantum-resistant cryptosystems from supersingular elliptic curve
isogenie"
     author:
       - ins: D. Jao
       - ins: L. De Feo
     date: 2011
     seriesinfo: PQCrypto-2011
     target: https://eprint.iacr.org/2011/506.pdf
  SIKE:
      title: "Supersingular Isogeny Key Encapsulation"
      date: 2017
      author:
        - ins: R. Azarderakhsh
        - ins: M. Campagna
        - ins: C. Costello
        - ins: L. De Feo
        - ins: B. Hess
        - ins: A. Jalali
        - ins: D. Jao
        - ins: B. Koziel
        - ins: B. LaMacchia
        - ins: P. Longa
        - ins: M. Naehrig
        - ins: J. Renes
        - ins: V. Soukharev
        - ins: D. Urbanik
      seriesinfo: Submission to the NIST Post-Quantum Standardization project
      target: http://sike.org/files/SIDH-spec.pdf

--- abstract

This draft specifies a TLS key exchange that combines the post-quantum key
exchange, Supersingular elliptic curve isogenie diffie-hellman (SIDH), with
elliptic curve Diffie-Hellman (ECDHE) key exchange.

--- middle

# Introduction

Supersingular elliptic curve isogenie diffie-hellman (SIDH) has been proposed
{{SIDH}} as a diffie-hellman like key-exchange protocol secure against quantum
computers.
Because there's not enough confidence in the security of SIDH yet it should only
be used in combination with a classical key-exchange scheme.

This document defines a way to combine {{eSIDH}} with the ECDHE key exchanges
defined in {{RFC7748}} for the TLS 1.3 {{!TLS13=I-D.ietf-tls-tls13}}
key-exchange.

`x25519` is combined with `sidh503` and `x448` is combined with `sidh751`.

## Performance Considerations

Both handshake partners have to compute the SIDH values in addition to the ECDHE
values, which requires additional time for computation.
The handshake messages also get larger because the SIDH values are added (see {{key-parameters}} for details).

## Notation

x25519 and x448 denote the ECDHE algorithms defined over the respective curve
from {{RFC7748}}.
sidh503 and sidh751 denote the SIDH algorithms defined using a prime of bit-length
`503` and `751` respectively.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.


# Hybrid SIDH-ECDHE Key Exchange

A hybrid key exchange takes the output of two separate key exchanges and mixes
the results in a secure way.

The ECDHE and SIDH shared secrets are calculated independently.  The shared
secret for ECDHE-SIDH is then the concatenation of the ECDHE and the SIDH shared
secrets.  For x25519sidh503 for example this is

    secret = x25519_secret || sidh_secret

The HKDF-Extract step used by TLS is relied on to combine entropy from both
secrets.

## ECDHE shared secret calculation

The ECDHE shared secret calculation is performed as described in Section 7.4.2 of {{TLS13}}.

## SIDH Key Exchange

This document uses primes p503 and p751 defined in {{eSIDH}} and {{SIKE}} for
sidh503 and sidh751.  See {{SIKE}} for details on how to compute key-exchange
messages and the shared secret.
Optimised versions of the algorithms mentioned here might be used.

### Field Element Representation {#sidh-representation}

Each element (`c=a+b*i`) of the underlying quadratic field GF(p^2) is encoded as
an array of bytes in little-endian order, i.e., the least significant octet
appears first, where each element `a,b` from GF(p) is encoded using `itoos` from
{{SIKE}} Section 1.2.6.
In particular, an element of GF(p) is converted to

    e_(n-1) * 256^(n-1) + ... + e_1 * 256 + e_0

with `n` 63 for p503 and 94 for p751. The octet representation of each element
is then the concatenation of `e_i` in little endian, i.e. `e_0||...||e_(n-1)`,
and the octet representation of element `c` is the concatenation of `a` and `b`,
`a||b`.

See `fp2toos` {{SIKE}} Section 1.2.6 to 1.2.8 for details.


### Key-exchange message generation {#sidh-keyexchange}

After choosing a private key each party computes its public key (P, Q, R) using
`isogen_l` from {{SIKE}} Section 1.3.5 and converts each element into octets (cf. {{sidh-representation}}).

See `pktoos` from {{SIKE}} Section 1.2.9 for details on converting the public
key to octets.

### Shared secret calculation

The SIDH shared secret is calculated as described in Section 1.3.6 of {{SIKE}}
using `isoex_l`.

Calculating SIDH shared secret requires each side to use isogenies of different
degree. This document assumes parameterizations as described in {{SIKE}}, which
is based on 4- and 3-power degree isogenies.
In order to calculate the shared secret, the client always generates an ephemeral
key pair based on 4-power degree isogenies. Accordingly, the server always
generates an ephemeral key pair based on 3-power degree isogenies.

The shared secret is a j-invariant and therefore an element of GF(p^2).
It is converted to octets as described in {{sidh-representation}}.

See `fp2toos` {{SIKE}} Section 1.2.6 to 1.2.8 for details.
All values are encoded without length prefixes or separators.


# Negotiated Groups

This document extends the enum of NamedGroups to use in the `supported_groups`
extension from TLS 1.3 {{TLS13}} Section 4.2.7.
The new codepoint for the "Supported Groups Registry" is:

    enum {
        ...,
        x25519sidh503(0x0105), x448sidh751(0x0106),
    } NamedGroup;


# ECDHE-SIDH key exchange parameters {#key-parameters}

This document defines ECDHE-SIDH parameters to use in the `key_share` extension
from TLS 1.3 (see Section 4.2.8 of {{TLS13}}).

ECDHE parameters for both clients and servers are encoded in the `key_exchange`
field of a KeyShareEntry as described in Section 4.2.8 of {{TLS13}} and
{{RFC7748}}.  SIDH parameters are appended to this value.

In particular, the contents are the serialised value of the following struct:

       struct {
           opaque X[coordinate_length];
           opaque P[sidh_coordinate_length];
           opaque Q[sidh_coordinate_length];
           opaque R[sidh_coordinate_length];
       } UncompressedPointRepresentation;

X is the public point from x25519 or x448 as described in {{RFC7748}}.

P, Q, and R are the binary representations of three field elements over
GF(p503^2) and GF(p751^2) respectively from the public SIDH key values as
described in {{sidh-keyexchange}}.
All values in the struct are encoded without length prefixes or separators.

Implementers MUST perform the checks to verify the SIDH public key as
specified in Section 9 of {{eSIDH}}.


# Security Considerations

Security of SIDH is based on the isogeny walk problem, assuming elliptic
curves between isogenies are supersingular (see {{SIKE}} chapter 4.1).
Algorithms solving this problem as well as usage of isogenies as drop-in
replacement for Diffie-Hellman are relatively young area of research.
Therefore the security behind the ECDHE-SIDH handshake does not rely on the
security of SIDH exclusively.

Idea behind ECDHE-SIDH hybrid scheme is to combine an existing key-agreement
algorithm with what's believed to be a quantum-resistant one. When large
quantum computers are available they will be able to break both x25519 and
x448. In this case the ECDHE-SIDH scheme is still safe assuming SIDH is secure.
On the other hand, if SIDH is found to be flawed, the hybrid scheme is still
secure against classical attacks assuming security of x25519/x448. Security
estimates for classical and quantum computers are provided in table below
based on {{SIKE}} and {{RFC7748}}. {{RNSL}} Chapter 1 provides introduction
to quantum resource estimates.

| Scheme        | Classical |  Quantum | NIST PQ category |
|---------------|-----------|----------|------------------|
| x25519sidh503 | 128-bit   | 64-qubit |      1           |
| x448sidh751   | 224-bit   | 96-qubit |      3           |

As described in {{ISOSEC}} it is possible to perform active attacks on
static-static or non-interactive variants of the SIDH scheme. The
countermeasure for this attack was described in {{KLM15}}. Research proposes
so-called "indirect key validation", using Fujisaki-Okamoto type transform.
However, using this transform is impractical and thus SIDH can be
considered secure only if used for ephemeral keys. A more detailed
discussion can be found in {{URBJAO}}.

Security against side-channel attacks is described in {{SIKE}}.

The security of the described key exchange relies on the security, in
particular the collision resistance, of the used key-derivation function.
TLS 1.3 uses HKDF {{RFC5869}} as its key-derivation function.
It is therefore important that the hash function used in HKDF is
collision-resistant.

# Test vectors
This section gives a test vectors for `x25519sidh503`.

## 1-RTT Handshake

Client SIDH-ECDHE public key:

    Public Key [Len: 411]
        01 2a 28 55 ff c3 44 b6 e5 1b 67 18 24 9f 8a 8d
        6a cb a8 57 ac a7 2e c9 d3 32 27 de e5 45 b7 c5
        6b 73 17 d2 ea de 38 7e 17 d5 3a 59 3c 64 37 cc
        d8 de de e6 46 d2 a4 cb 42 b5 95 36 48 fd 16 09
        6f 24 6c b5 f8 8f ce 66 da 60 6e b9 f7 d8 19 00
        f8 03 e7 6e 4a e6 a6 23 84 7a f7 e8 2f 52 4b 35
        1c eb 17 c3 b4 4e 82 3d 3b ff df 2d f3 63 5e a0
        0f 00 88 b9 01 2f c3 ce da 04 f2 13 e2 d8 3d ba
        62 26 c0 dd 77 d7 cc 46 25 c1 d5 04 67 c0 17 c7
        41 89 37 48 9b 4d 87 2f 5c 50 56 16 40 72 2c 29
        39 e0 10 2b 9c 69 2b dc ab a8 84 2d 83 d1 a7 1f
        c7 d1 06 68 e4 02 cc 82 d2 9b 59 4c 7a 3e 7b 9a
        d2 fa 28 2f 91 db 49 3c b8 a1 e8 a8 c8 6b 7a e8
        da d6 6b fb a2 72 74 ba 02 4e ff 7e 07 93 61 78
        c4 a6 8a 72 9e 8a 7d ab 8a d2 f6 4d a0 d1 c1 8f
        89 48 81 aa d4 80 7c b2 f1 dd 60 9b 33 f8 7d 0c
        ad 4e 8f db 9b 79 39 71 be d9 9a 5b 0f a2 f5 20
        29 2e ed 35 16 4c 5f 9e d0 a4 4f 5a a6 09 f4 96
        3b a8 4e ed 4b 60 ef 8f 04 13 04 a0 b2 3d 5e e0
        0c 86 92 6a 49 31 1c e6 d6 ef 0a 28 04 0d 00 df
        97 15 88 17 08 59 b9 b5 29 79 34 6a e0 f6 63 c5
        28 c5 8f ec 91 d9 c1 3c ea d8 44 44 48 46 0f f1
        f3 9e 0c ed ac 26 c8 2c f7 6a 08 cc 28 a6 44 68
        5b 18 b7 41 18 ab 64 5f be 60 15 a8 e5 a8 5b 94
        13 4f 9d ab 03 65 eb 38 62 86 ef 6a f8 cb ef a0
        2f 95 d4 18 8e d2 42 b6 b8 7d 2e

Client SIDH-ECDHE private key:

    Private Key [Len: 176]
        6d d0 54 a9 89 24 72 f1 51 64 04 30 e2 2f 7d c0
        46 78 d4 76 fd 3a a7 3a 11 92 b3 dd cc 68 57 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        b0 05 f8 ae 30 56 00 00 20 ee f7 ae 30 56 00 00

Client Hello:

    CH [Len: 523]
        01 00 02 07 03 03 21 25 ef b7 aa c5 21 be f8 16
        61 56 a9 bb 96 25 fd b9 b7 ac e6 0d 9a 89 8d 9e
        5e 3d 2f 3b 17 b2 00 00 02 13 01 01 00 01 dc 00
        00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01
        00 01 00 00 0a 00 04 00 02 01 05 00 33 01 a1 01
        9f 01 05 01 9b 01 2a 28 55 ff c3 44 b6 e5 1b 67
        18 24 9f 8a 8d 6a cb a8 57 ac a7 2e c9 d3 32 27
        de e5 45 b7 c5 6b 73 17 d2 ea de 38 7e 17 d5 3a
        59 3c 64 37 cc d8 de de e6 46 d2 a4 cb 42 b5 95
        36 48 fd 16 09 6f 24 6c b5 f8 8f ce 66 da 60 6e
        b9 f7 d8 19 00 f8 03 e7 6e 4a e6 a6 23 84 7a f7
        e8 2f 52 4b 35 1c eb 17 c3 b4 4e 82 3d 3b ff df
        2d f3 63 5e a0 0f 00 88 b9 01 2f c3 ce da 04 f2
        13 e2 d8 3d ba 62 26 c0 dd 77 d7 cc 46 25 c1 d5
        04 67 c0 17 c7 41 89 37 48 9b 4d 87 2f 5c 50 56
        16 40 72 2c 29 39 e0 10 2b 9c 69 2b dc ab a8 84
        2d 83 d1 a7 1f c7 d1 06 68 e4 02 cc 82 d2 9b 59
        4c 7a 3e 7b 9a d2 fa 28 2f 91 db 49 3c b8 a1 e8
        a8 c8 6b 7a e8 da d6 6b fb a2 72 74 ba 02 4e ff
        7e 07 93 61 78 c4 a6 8a 72 9e 8a 7d ab 8a d2 f6
        4d a0 d1 c1 8f 89 48 81 aa d4 80 7c b2 f1 dd 60
        9b 33 f8 7d 0c ad 4e 8f db 9b 79 39 71 be d9 9a
        5b 0f a2 f5 20 29 2e ed 35 16 4c 5f 9e d0 a4 4f
        5a a6 09 f4 96 3b a8 4e ed 4b 60 ef 8f 04 13 04
        a0 b2 3d 5e e0 0c 86 92 6a 49 31 1c e6 d6 ef 0a
        28 04 0d 00 df 97 15 88 17 08 59 b9 b5 29 79 34
        6a e0 f6 63 c5 28 c5 8f ec 91 d9 c1 3c ea d8 44
        44 48 46 0f f1 f3 9e 0c ed ac 26 c8 2c f7 6a 08
        cc 28 a6 44 68 5b 18 b7 41 18 ab 64 5f be 60 15
        a8 e5 a8 5b 94 13 4f 9d ab 03 65 eb 38 62 86 ef
        6a f8 cb ef a0 2f 95 d4 18 8e d2 42 b6 b8 7d 2e
        00 2b 00 03 02 7f 1c 00 0d 00 04 00 02 05 03 00
        2d 00 02 01 01 00 1c 00 02 40 01

Server SIDH-ECDHE public key:

    Public Key [Len: 411]
        00 b8 61 f3 5b 76 b1 bc c3 64 6f 1a ef 42 6f 96
        f8 4d 58 9c ec 63 2c 3d ad 6f 56 18 3c d0 09 c7
        aa 9b 28 08 a9 6e ea 82 97 8f fd a6 e8 60 39 f0
        8d 28 b1 fa 6a fb 16 f4 6e 05 f8 28 c4 4a 26 3a
        55 ef 0e ef b4 4f 24 b0 f9 5c c2 3f 43 ac cd f5
        03 42 57 19 f2 1b bd 42 ae a7 a0 21 c8 31 e1 a2
        3e 21 ee cc 66 ab 52 28 72 70 02 aa e4 78 da af
        6f 66 51 c1 11 d3 4e 99 79 9f c7 ac 22 bb 2c 59
        f8 07 45 c1 b7 30 49 44 a5 2e a3 00 b4 a8 a2 9f
        b2 07 6e 2f c2 ea 4f a6 43 3c 28 bc 60 e8 16 37
        71 4a fd 71 fb 57 de 77 03 8d 0a dd c8 0b fc 00
        b2 da cb e7 fc 9d 2b cc 9e 53 a7 6c 70 3c 08 f5
        59 b3 d7 22 b7 68 bb a8 1e 91 23 7e 1c 4c d1 44
        c8 d0 aa 3c 2b 5c e5 3f 8e af aa 2b ae e4 a1 a9
        a5 b3 a7 42 ad 70 5b 38 9c a5 77 e6 58 b1 7b 86
        b9 0b 60 53 21 c3 96 e0 20 5b b9 f8 13 2e 52 30
        5c 05 35 34 84 bd d5 ee b3 9a de e9 ac d3 10 48
        5f 3b ab f4 19 03 73 a8 0f 88 89 c3 95 0f 5c 1b
        79 5f d1 d1 36 4f 42 ff e9 6b 52 ff f1 08 81 e9
        36 c4 08 53 46 42 54 04 20 46 62 29 80 6e 54 93
        bf 10 85 16 26 fd 89 b9 01 b3 15 7e 81 3a 52 96
        1d b5 b8 0b 7a 11 e0 0b d2 ba 79 3d 3f ce e0 ab
        c2 26 99 5c eb 99 58 07 40 30 3c 89 4b 95 70 8a
        fd f1 e1 3c 54 a6 fc e4 44 e7 0c 69 30 4b 52 c5
        6a b0 99 3a 39 e1 c3 f8 e4 7d ab 03 fb 88 8e e6
        6f 69 39 3c d1 a8 b3 a3 39 75 3d

Server SIDH-ECDHE private key:

    Private Key [Len: 176]
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        aa 67 36 95 6d 4c 33 84 ca 8e 8c 79 db 0e 1b 3b
        e4 08 41 c4 49 f4 65 36 6c 17 2b 47 90 21 e5 82
        79 0c a6 9c 6e 20 2c b8 74 b8 63 56 87 50 f5 cb
        1e 70 9e 09 53 78 52 f0 ed cb 31 73 6c 36 14 03
        11 35 0a 28 a3 88 23 6c 4b b4 bd bd ec 9f 01 1d
        d6 a1 e7 d5 6e d7 11 56 62 a2 2a 44 3b 5f 11 67
        02 1c d0 70 89 0e f2 68 06 d1 c4 cc d8 e1 30 ee
        8a 94 cf 1e 2e c4 e2 38 8d fe 92 72 db 3d 00 00
        a0 db f8 ae 30 56 00 00 70 d1 f8 ae 30 56 00 00

Server Handshake:

    SH [Len: 469]
        02 00 01 d1 03 03 ed 5d dc c5 1c 83 e4 2a 15 6a
        80 8c 72 7a 2f a4 a5 e8 b3 88 d2 3d bf 60 93 a3
        23 fd fb 90 a4 bd 00 13 01 00 01 a9 00 33 01 9f
        01 05 01 9b 00 b8 61 f3 5b 76 b1 bc c3 64 6f 1a
        ef 42 6f 96 f8 4d 58 9c ec 63 2c 3d ad 6f 56 18
        3c d0 09 c7 aa 9b 28 08 a9 6e ea 82 97 8f fd a6
        e8 60 39 f0 8d 28 b1 fa 6a fb 16 f4 6e 05 f8 28
        c4 4a 26 3a 55 ef 0e ef b4 4f 24 b0 f9 5c c2 3f
        43 ac cd f5 03 42 57 19 f2 1b bd 42 ae a7 a0 21
        c8 31 e1 a2 3e 21 ee cc 66 ab 52 28 72 70 02 aa
        e4 78 da af 6f 66 51 c1 11 d3 4e 99 79 9f c7 ac
        22 bb 2c 59 f8 07 45 c1 b7 30 49 44 a5 2e a3 00
        b4 a8 a2 9f b2 07 6e 2f c2 ea 4f a6 43 3c 28 bc
        60 e8 16 37 71 4a fd 71 fb 57 de 77 03 8d 0a dd
        c8 0b fc 00 b2 da cb e7 fc 9d 2b cc 9e 53 a7 6c
        70 3c 08 f5 59 b3 d7 22 b7 68 bb a8 1e 91 23 7e
        1c 4c d1 44 c8 d0 aa 3c 2b 5c e5 3f 8e af aa 2b
        ae e4 a1 a9 a5 b3 a7 42 ad 70 5b 38 9c a5 77 e6
        58 b1 7b 86 b9 0b 60 53 21 c3 96 e0 20 5b b9 f8
        13 2e 52 30 5c 05 35 34 84 bd d5 ee b3 9a de e9
        ac d3 10 48 5f 3b ab f4 19 03 73 a8 0f 88 89 c3
        95 0f 5c 1b 79 5f d1 d1 36 4f 42 ff e9 6b 52 ff
        f1 08 81 e9 36 c4 08 53 46 42 54 04 20 46 62 29
        80 6e 54 93 bf 10 85 16 26 fd 89 b9 01 b3 15 7e
        81 3a 52 96 1d b5 b8 0b 7a 11 e0 0b d2 ba 79 3d
        3f ce e0 ab c2 26 99 5c eb 99 58 07 40 30 3c 89
        4b 95 70 8a fd f1 e1 3c 54 a6 fc e4 44 e7 0c 69
        30 4b 52 c5 6a b0 99 3a 39 e1 c3 f8 e4 7d ab 03
        fb 88 8e e6 6f 69 39 3c d1 a8 b3 a3 39 75 3d 00
        2b 00 02 7f 1c

    SH [Len: 551]
        08 00 00 14 00 12 00 0a 00 04 00 02 01 05 00 1c
        00 02 40 01 00 00 00 00 0b 00 01 78 00 00 01 74
        00 01 6f 30 82 01 6b 30 81 f2 a0 03 02 01 02 02
        01 0c 30 0a 06 08 2a 86 48 ce 3d 04 03 02 30 13
        31 11 30 0f 06 03 55 04 03 13 08 65 63 64 73 61
        33 38 34 30 1e 17 0d 31 38 30 36 31 30 31 30 32
        34 31 34 5a 17 0d 32 38 30 36 31 30 31 30 32 34
        31 34 5a 30 13 31 11 30 0f 06 03 55 04 03 13 08
        65 63 64 73 61 33 38 34 30 76 30 10 06 07 2a 86
        48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04
        f9 c9 0d 79 b5 87 c5 8d f0 84 79 99 15 61 14 14
        bf 3d 33 04 dc 0e fc de 82 0e 38 35 58 a9 3a f8
        88 25 ca 9b aa 77 73 82 e4 b2 9a 6c 67 54 f3 4d
        0f 17 f4 06 94 3a 08 19 8e 92 69 d2 f7 a8 04 57
        70 24 c2 01 f1 b7 0b b3 cd 1b dd 03 4d 45 09 68
        f8 cb cf c7 b3 5b 29 9f 35 d9 ea e7 6d d0 93 8a
        a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30
        0b 06 03 55 1d 0f 04 04 03 02 07 80 30 0a 06 08
        2a 86 48 ce 3d 04 03 02 03 68 00 30 65 02 31 00
        c4 44 a1 03 fe 2e 80 eb e0 a8 2b 70 02 84 ef f2
        ca 82 9a e7 db d3 06 40 56 c9 da 5b 36 0b 85 f5
        10 e6 f2 da 54 9c b3 65 81 37 46 98 c8 5a 87 18
        02 30 46 18 b8 3b 7f 9f db aa 2b 0a f9 ad fa 11
        e4 2e 83 cd 57 72 c3 a5 79 d4 04 10 81 d5 d1 07
        70 ba 85 db 5b ff 3d 2a 60 8d a6 4c e5 c9 1c ed
        bb 12 00 00 0f 00 00 6b 05 03 00 67 30 65 02 30
        2d cf 37 77 8f 03 9f e5 12 4c 22 89 21 12 f8 f5
        19 32 69 0b d2 35 9a bb 51 ea 25 89 08 ff f0 65
        8d 88 16 ba 1b 7b 1d c6 0a 59 5d 55 8a 3b b8 d6
        02 31 00 e0 5f a4 57 7e b5 85 b2 fe 62 23 b9 7e
        fc a8 af b3 8d f8 28 ae 04 e7 fa d6 7b 33 66 b6
        04 32 b1 6b f8 20 1e 03 76 12 ad cb 60 40 7b 6a
        1a f0 cd 14 00 00 20 16 cd 2b bc 21 d8 55 1a ab
        9b a6 c9 ce 5b fd 06 95 2a 56 55 6b b3 6e 74 70
        6c 28 10 98 c0 28 7e

Client finished handshake:

    Client finished [Len: 36]
        14 00 00 20 d9 33 cd 30 1a 27 b8 b3 dc c7 68 cf
        f9 bc b6 ca d6 cf 6f cb 31 eb dc e3 95 71 69 b1
        11 15 44 f8

# IANA Considerations

TODO: register the codepoints


--- back

# Acknowledgements
{:numbered="false"}

* Martin Thomson \\
  Mozilla \\
  mt@mozilla.com
