---
title: Post-Quantum key-exchange in TLS
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
  X962:
       title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
       date: 1998
       author:
         org: ANSI
       seriesinfo:
         ANSI: X9.62

normative:
  RFC7748:
  RFC2119:
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
This document defines a way to combine `p751sidh` {{eSIDH}} with ECDHE for the
TLS 1.3 {{TLS13}} key-exchange.
Note that this is different from the recommended combindation in {{eSIDH}}
because it allows using standardised elliptic curves for ECDHE {{X962}}{{RFC7748}}.

## Performance Considerations

Both handshake partners have to compute the SIDH values in addition to the ECDHE
values, which requires additional time for computation.
The handshake messages also get larger because the SIDH values are added.

## Notation

TODO: describe necessary SIDH parameters.

## Terminology
RFC 2119 {{RFC2119}} defines the terms MUST, SHOULD, and MAY.

# SIDH p751

TODO: describe.

# Negotiated Groups

This document extends the enum of NamedGroups to use in the `supported_groups`
extension from TLS 1.3 {{TLS13}} Section 4.2.7.
The new codepoint for the "Supported Groups Registry" is:

    enum {
    // other already defined elliptic curves (see TLS1.3 RFC)
        ecdhesidh751(0x0105),
    //
    } NamedGroup;

TODO: describe parameters.

# ECDHE-SIDH key exchange parameters

This document defines ECDHE-SIDH parameters to use in the `key_share` extension
from TLS 1.3 {{TLS13}} Section 4.2.8.
ECDHE parameters for both clients and servers are encoded in the key_exchange
field of a KeyShareEntry as described in {{TLS13}} Section 4.2.8 and
{{RFC7748}} described.

In particular, for secp256r1, secp384r1 and secp521r1, the contents are the
serialised value of the following struct:

       struct {
           uint8 legacy_form = 4;
           opaque X[coordinate_length];
           opaque Y[coordinate_length];
           opaque S[sidh_coordinate_length];
           opaque P[sidh_coordinate_length];
           opaque Q[sidh_coordinate_length];
       } UncompressedPointRepresentation;

X and Y are as described in {{TLS13}} Section 4.2.8
For X25519 and X448 the contents are the serialised value of the following
struct:

       struct {
           opaque X[coordinate_length];
           opaque S[sidh_coordinate_length];
           opaque P[sidh_coordinate_length];
           opaque Q[sidh_coordinate_length];
       } UncompressedPointRepresentation;

X is as described in {{RFC7748}}.
S, P, and Q are the binary representations three field elements from the public
SIDH key values in network byte order.
TODO: how long is that?
TODO: SIDH key validation

# ECDHE-SIDH Shared Secret Calculation

The ECDHE and SIDH shared secrets are calculated independently.
The shared secret for ECDHE-SIDH is then the concatenation of the ECDHE and the SIDH shared secrets.

## ECDHE shared secret calculation
The ECDHE shared secret calculation is performed as described in {{TLS13}} Section 7.4.2.

## SIDH shared secret calculation
The SIDH shared secret is calculated as described in {{eSIDH}} Section 6.
TODO: describe.

# Security Considerations

TODO: This is at least as secure as the used ECDH.

# IANA Considerations

This document makes no requests of IANA yet.

# Acknowledgements


--- back