# stun

STUN and TURN library for Erlang / Elixir.

Both [STUN](https://en.wikipedia.org/wiki/STUN) (Session Traversal
Utilities for NAT) and
[TURN](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT)
standards are used as technics to establish media connection between
peers for VoIP (for example using
[SIP](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) or
[Jingle](http://xmpp.org/about-xmpp/technology-overview/jingle/)) and
[WebRTC](https://en.wikipedia.org/wiki/WebRTC).

They are part of a more general negociation technique know as
[ICE](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment)
(Interactive Connectivity Establishment).

To summarize:

* A STUN server is used to get an external network address. It does
  not serve as a relay for the mediat raffic.
* TURN servers are used to relay traffic if direct (peer to peer)
  connection fails.

## Build

This is a pure Erlang implementation, so you do not need to have
specific C libraries installed.

### Generic build

You can trigger build with:

    make

# Usage

TODO

# References

You can refer to IETF specifications to learn more:

* [RFC 5389](https://tools.ietf.org/html/rfc5389): Session Traversal
  Utilities for NAT (STUN).
* [RFC 5766](https://tools.ietf.org/html/rfc5766): Traversal Using
  Relays around NAT (TURN): Relay Extensions to STUN.
* [RFC 5245](https://tools.ietf.org/html/rfc5245): Interactive
  Connectivity Establishment (ICE): A Protocol for NAT Traversal for
  Offer/Answer Protocols.
* [RFC 6544](https://tools.ietf.org/html/rfc6544): TCP Candidates with
  Interactive Connectivity Establishment (ICE)
