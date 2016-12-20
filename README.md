# STUN

[![Build Status](https://travis-ci.org/processone/stun.svg?branch=master)](https://travis-ci.org/processone/stun) [![Coverage Status](https://coveralls.io/repos/processone/stun/badge.svg?branch=master&service=github)](https://coveralls.io/github/processone/stun?branch=master) [![Hex version](https://img.shields.io/hexpm/v/stun.svg "Hex version")](https://hex.pm/packages/stun)

STUN and TURN library for Erlang / Elixir.

Both [STUN](https://en.wikipedia.org/wiki/STUN) (Session Traversal
Utilities for NAT) and
[TURN](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT)
standards are used as technics to establish media connection between
peers for VoIP (for example using
[SIP](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) or
[Jingle](http://xmpp.org/about-xmpp/technology-overview/jingle/)) and
[WebRTC](https://en.wikipedia.org/wiki/WebRTC).

They are part of a more general negotiation technique know as
[ICE](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment)
(Interactive Connectivity Establishment).

To summarize:

* A STUN server is used to get an external network address. It does
  not serve as a relay for the mediat raffic.
* TURN servers are used to relay traffic if direct (peer to peer)
  connection fails.

## Build

This is a pure Erlang implementation, so you do not need to have
specific C libraries installed for the STUN, TURN, ICE code.

However, this code depends on ProcessOne
[Fast TLS](https://github.com/processone/fast_tls), which depends on
OpenSSL 1.0.0+ library.

### Generic build

You can trigger build with:

    make

# Usage

The following sequence describe a STUN establishment.

First, start the application and stun listener:

```
1> application:start(stun).
ok
2> stun_listener:add_listener(3478, udp, []).
ok
```

Then, you can form and send a BindRequest:

```
3> rr(stun).
[state,stun,turn]
4> random:seed(erlang:timestamp()).
undefined
```

You can form a transaction id. Should be always 96 bit:

```
5> TrID = random:uniform(1 bsl 96).
41809861624941132369239212033
```

You then create a BindRequest message.

`16#001` is `?STUN_METHOD_BINDING`, defined in `include/stun.hrl`

```
6> Msg = #stun{method = 16#001, class = request, trid = TrID}.
#stun{class = request,method = 1,magic = 554869826,
     trid = 41809861624941132369239212033,raw = <<>>,
     unsupported = [],'ALTERNATE-SERVER' = undefined,
     'CHANNEL-NUMBER' = undefined,'DATA' = undefined,
     'DONT-FRAGMENT' = false,'ERROR-CODE' = undefined,
     'LIFETIME' = undefined,'MAPPED-ADDRESS' = undefined,
     'MESSAGE-INTEGRITY' = undefined,'NONCE' = undefined,
     'REALM' = undefined,'REQUESTED-TRANSPORT' = undefined,
     'SOFTWARE' = undefined,'UNKNOWN-ATTRIBUTES' = [],
     'USERNAME' = undefined,'XOR-MAPPED-ADDRESS' = undefined,
     'XOR-PEER-ADDRESS' = [],'XOR-RELAYED-ADDRESS' = undefined}
```

You can then establish connection to running server:

```
7> {ok, Socket} = gen_udp:open(0, [binary, {ip,
7> {127,0,0,1}},{active,false}]).
{ok,#Port<0.1020>}
8> {ok, Addr} = inet:sockname(Socket).
{ok,{{127,0,0,1},41906}}
```

The following call is for encoding BindRequest:

```
9> PktOut = stun_codec:encode(Msg).
<<0,1,0,0,33,18,164,66,135,24,78,148,65,4,128,0,0,0,0,1>>
```

The BindRequest can then be send:

```
10> gen_udp:send(Socket, {127,0,0,1}, 3478, PktOut).
ok
```

The follow code receives the BindResponse:

```
11> {ok, {_, _, PktIn}} = gen_udp:recv(Socket, 0).
{ok,{{127,0,0,1},
    3478,
    <<1,1,0,32,33,18,164,66,135,24,78,148,65,4,128,0,0,0,0,
      1,128,34,0,15,...>>}}
```

You can then decode the BindResponse:

```
12> {ok, Response} = stun_codec:decode(PktIn, datagram).
{ok,#stun{class = response,method = 1,magic = 554869826,
         trid = 41809861624941132369239212033,raw = <<>>,
         unsupported = [],'ALTERNATE-SERVER' = undefined,
         'CHANNEL-NUMBER' = undefined,'DATA' = undefined,
         'DONT-FRAGMENT' = false,'ERROR-CODE' = undefined,
         'LIFETIME' = undefined,'MAPPED-ADDRESS' = undefined,
         'MESSAGE-INTEGRITY' = undefined,'NONCE' = undefined,
         'REALM' = undefined,'REQUESTED-TRANSPORT' = undefined,
         'SOFTWARE' = <<"P1 STUN library">>,
         'UNKNOWN-ATTRIBUTES' = [],'USERNAME' = undefined,
         'XOR-MAPPED-ADDRESS' = {{127,0,0,1},41906},
         'XOR-PEER-ADDRESS' = [],'XOR-RELAYED-ADDRESS' = undefined}}
```

Finally, checking 'XOR-MAPPED-ADDRESS' attribute, should be equal to locally
binded address:

```
13> Addr == Response#stun.'XOR-MAPPED-ADDRESS'.
true
```

## Development

### Test

#### Unit test

You can run eunit test with the command:

    make test

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
