---
title: Hybrid ECDH-SIDH Key Exchange for TLS
abbrev: pq-tls
docname: draft-kiefer-pq-tls-latest
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
  SIDH:
     title: "Towards quantum-resistant cryptosystems from supersingular elliptic curve
isogenie"
     author:
       - ins: D. Jao
       - ins: L. De Feo
     date: 2011
     seriesinfo: PQCrypto-2011
     target: https://eprint.iacr.org/2011/506.pdf
  sike:
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

normative:
  RFC7748:
  RFC2119:
  RFC5869:
  TLS13:
     title: "The Transport Layer Security (TLS) Protocol Version 1.3"
     author:
       - ins: E. Rescorla
     target: https://tools.ietf.org/html/draft-ietf-tls-tls13-28
     date: 2018
        

--- abstract

To allow interopability testing of post-quantum key-exchange algorithms this
draft specifies a secure way to combine SIDH with ECDHE in TLS handshakes.

--- middle

# Introduction

Supersingular elliptic curve isogenie diffie-hellman (SIDH) has been proposed
{{SIDH}} as a diffie-hellman like key-exchange protocol secure against quantum
computers.
Because there's not enough confidence in the security of SIDH yet it should only
be used in combination with a classical key-exchange scheme.
This document defines a way to combine {{eSIDH}} with ECDHE for the
TLS 1.3 {{TLS13}} key-exchange.
Note that this is different from the recommended combindation in {{eSIDH}}
because it uses standardised elliptic curves for ECDHE {{RFC7748}}.
In particular `x25519` is combined with `sidh503` and `x448` is combined with `sidh751`.

## Performance Considerations

Both handshake partners have to compute the SIDH values in addition to the ECDHE
values, which requires additional time for computation.
The handshake messages also get larger because the SIDH values are added (see {{key-parameters}} for details).

## Notation

x25519 and x448 denote the ECDHE algorithms defined over the respective curve
from {{RFC7748}}.
sidh503 and sidh751 denote the SIDH algorithms defined using prime of bit-length
`p=503` and `751` respectively.

## Terminology
RFC 2119 {{RFC2119}} defines the terms MUST, SHOULD, and MAY.

# Supersingular elliptic curve Isogenie Diffie-Hellman (SIDH)

See {{eSIDH}} for details on how to compute key-exchange messages and the
shared secret.
This document uses p508 and p751 defined in {{eSIDH}}{{sike}}.

# Negotiated Groups

This document extends the enum of NamedGroups to use in the `supported_groups`
extension from TLS 1.3 {{TLS13}} Section 4.2.7.
The new codepoint for the "Supported Groups Registry" is:

    enum {
    // other already defined elliptic curves (see TLS1.3 RFC)
        x25519sidh503(0x0105), x448sidh751(0x0106),
    //
    } NamedGroup;


# ECDHE-SIDH key exchange parameters {#key-parameters}

This document defines ECDHE-SIDH parameters to use in the `key_share` extension
from TLS 1.3 {{TLS13}} Section 4.2.8.
ECDHE parameters for both clients and servers are encoded in the key_exchange
field of a KeyShareEntry as described in {{TLS13}} Section 4.2.8 and
{{RFC7748}} described.

In particular, the contents are the serialised value of the following struct:

       struct {
           opaque X[coordinate_length];
           opaque S[sidh_coordinate_length];
           opaque P[sidh_coordinate_length];
           opaque Q[sidh_coordinate_length];
       } UncompressedPointRepresentation;

X is the public point from x25519 or x448  as described in {{RFC7748}}.
S, P, and Q are the binary representations of three field elements over
GF(p503^2) and GF(p751^2) respectively from the public SIDH key values in
network byte order.
Elements over GF(p503) are encoded in 63 octets in little endian format, i.e.,
the least significant octet is located in the lowest memory address.
Elements (a+b\*i) over GF(p503^2), where a and b are defined over
GF(p503), are encoded as {a, b}, with a in the lowest memory portion.
GF(p751) is accordingly encoded into 94 octets.
All values in the struct are encoded without length prefixes or separators.

Implementers SHOULD perform the checks to verify the SIDH public key as
specified in Section 9 of {{eSIDH}}.

# ECDHE-SIDH Shared Secret Calculation

The ECDHE and SIDH shared secrets are calculated independently.
The shared secret for ECDHE-SIDH is then the concatenation of the ECDHE and the SIDH shared secrets.
For x25519sidh503 for example this is

    secret = x25519_secret || sidh_secret

## ECDHE shared secret calculation
The ECDHE shared secret calculation is performed as described in {{TLS13}} Section 7.4.2.

## SIDH shared secret calculation
The SIDH shared secret is calculated as described in {{eSIDH}} Section 6.
The result is an element in GF(p^2).

# Security Considerations

The security of SIDH is not well understood at this point.
Therefore the security of the ECDHE-SIDH handshake MUST NOT rely on the security
of SIDH.
The security of the described key exchange relies on the security, in particular
the collision resistence, of the used key-derivation function.
TLS 1.3 uses HKDF as defined in {{RFC5869}} as key-derivation function.
It is therefore important the hash function used in HKDF is collision-resistant.
With these assumptions ECDHE-SIDH is at least as secure as the used ECDHE.

# IANA Considerations

This document makes no requests of IANA yet.

# Acknowledgements


--- back