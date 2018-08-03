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

# IANA Considerations

TODO: register the codepoints


--- back

# Acknowledgements
{:numbered="false"}

* Martin Thomson \\
  Mozilla \\
  mt@mozilla.com
