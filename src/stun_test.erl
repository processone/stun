%%%-------------------------------------------------------------------
%%% File    : stun_test.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : STUN test suite
%%% Created :  7 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2017 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------

-module(stun_test).

-export([bind_udp/2, bind_tcp/2, allocate_udp/5]).

-define(STUN_PORT, 34780).
-define(STUNS_PORT, 53490).
-define(RECV_TIMEOUT, timer:seconds(5)).
-define(CHANNEL, 16#4000).
-define(REALM, <<"localhost">>).
-define(USER, <<"user">>).
-define(PASS, <<"pass">>).

-include_lib("eunit/include/eunit.hrl").
-include("stun.hrl").

init_test() ->
    ?assertEqual(ok, application:start(fast_tls)),
    ?assertEqual(ok, application:start(stun)).

mk_cert_test() ->
    ?assertEqual(ok, file:write_file("certfile.pem", get_cert())).

add_udp_listener_test() ->
    ?assertEqual(ok, stun_listener:add_listener(
		       ?STUN_PORT, udp,
		       [use_turn,
			{auth_type, user},
			{auth_realm, ?REALM},
			{auth_fun, fun(?USER, ?REALM) -> ?PASS;
				      (_, _) -> <<"">>
				   end}])).

add_tcp_listener_test() ->
    ?assertEqual(ok, stun_listener:add_listener(?STUN_PORT, tcp, [])).

add_tls_listener_test() ->
    ?assertEqual(ok, stun_listener:add_listener(
		       ?STUNS_PORT, tcp, [tls, {certfile, "certfile.pem"}])).

bind_udp_test() ->
    TrID = mk_trid(),
    Msg = #stun{method = ?STUN_METHOD_BINDING,
 		class = request,
 		trid = TrID},
    {ok, Socket} = gen_udp:open(0, [binary, {ip, {127,0,0,1}}, {active, false}]),
    {ok, Addr} = inet:sockname(Socket),
    PktOut = stun_codec:encode(Msg),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut)),
    {ok, {_, _, PktIn}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    ?assertMatch(
       {ok, #stun{trid = TrID,
		  'XOR-MAPPED-ADDRESS' = Addr}},
       stun_codec:decode(PktIn, datagram)),
    ?assertEqual(ok, gen_udp:close(Socket)).

bind_tcp_test() ->
    TrID = mk_trid(),
    Msg = #stun{method = ?STUN_METHOD_BINDING,
 		class = request,
 		trid = TrID},
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, ?STUN_PORT,
				   [binary, {active, false}]),
    {ok, Addr} = inet:sockname(Socket),
    Pkt = stun_codec:encode(Msg),
    ?assertEqual(ok, gen_tcp:send(Socket, Pkt)),
    ?assertMatch(
       {ok, #stun{trid = TrID,
		  'XOR-MAPPED-ADDRESS' = Addr}},
       recv(Socket, <<>>, false)),
    ?assertEqual(ok, gen_tcp:close(Socket)).

bind_tls_test() ->
    TrID = mk_trid(),
    Msg = #stun{method = ?STUN_METHOD_BINDING,
 		class = request,
 		trid = TrID},
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, ?STUNS_PORT,
				   [binary, {active, true}]),
    {ok, TLSSocket} = fast_tls:tcp_to_tls(
			Socket, [{certfile, <<"certfile.pem">>}, connect]),
    ?assertEqual({ok, <<>>}, fast_tls:recv_data(TLSSocket, <<>>)),
    {ok, Addr} = fast_tls:sockname(TLSSocket),
    Pkt = stun_codec:encode(Msg),
    recv(TLSSocket, <<>>, true),
    ?assertEqual(ok, fast_tls:send(TLSSocket, Pkt)),
    ?assertMatch(
       {ok, #stun{trid = TrID,
		  'XOR-MAPPED-ADDRESS' = Addr}},
       recv(TLSSocket, <<>>, true)),
    ?assertEqual(ok, gen_tcp:close(Socket)).

del_tcp_listener_test() ->
    ?assertEqual(ok, stun_listener:del_listener(?STUN_PORT, tcp)).

del_tls_listener_test() ->
    ?assertEqual(ok, stun_listener:del_listener(?STUNS_PORT, tcp)).

allocate_udp_test() ->
    {ok, Socket} = gen_udp:open(0, [binary, {ip, {127,0,0,1}}, {active, false}]),
    {ok, PeerSocket} = gen_udp:open(0, [binary, {ip, {127,0,0,1}}, {active, false}]),
    {ok, PeerAddr} = inet:sockname(PeerSocket),
    {ok, Addr} = inet:sockname(Socket),
    %% Allocating address, receiving 401 with nonce and realm
    TrID1 = mk_trid(),
    Msg1 = #stun{method = ?STUN_METHOD_ALLOCATE,
		 class = request,
		 trid = TrID1},
    PktOut1 = stun_codec:encode(Msg1),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut1)),
    {ok, {_, _, PktIn1}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    {ok, #stun{trid = TrID1,
	       class = error,
	       'ERROR-CODE' = {401, _},
	       'NONCE' = Nonce,
	       'REALM' = ?REALM}} = stun_codec:decode(PktIn1, datagram),
    %% Repeating allocation from the first step
    TrID2 = mk_trid(),
    Msg2 = #stun{method = ?STUN_METHOD_ALLOCATE,
		 trid = TrID2,
		 'REQUESTED-TRANSPORT' = udp,
		 'NONCE' = Nonce,
		 'REALM' = ?REALM,
		 'USERNAME' = ?USER},
    PktOut2 = stun_codec:encode(Msg2, {?USER, ?REALM, ?PASS}),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut2)),
    {ok, {_, _, PktIn2}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    {ok, #stun{trid = TrID2,
	       class = response,
	       'XOR-RELAYED-ADDRESS' = {RelayIP, RelayPort},
	       'XOR-MAPPED-ADDRESS' = Addr}} = stun_codec:decode(PktIn2, datagram),
    %% Creating permission for the peer
    TrID3 = mk_trid(),
    Msg3 = #stun{method = ?STUN_METHOD_CREATE_PERMISSION,
		 trid = TrID3,
		 'XOR-PEER-ADDRESS' = [PeerAddr],
		 'NONCE' = Nonce,
		 'REALM' = ?REALM,
		 'USERNAME' = ?USER},
    PktOut3 = stun_codec:encode(Msg3, {?USER, ?REALM, ?PASS}),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut3)),
    {ok, {_, _, PktIn3}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    {ok, #stun{trid = TrID3,
	       class = response}} = stun_codec:decode(PktIn3, datagram),
    %% Sending some data to the peer. Peer receives it.
    Data1 = crypto:rand_bytes(20),
    TrID4 = mk_trid(),
    Msg4 = #stun{method = ?STUN_METHOD_SEND,
		 trid = TrID4,
		 class = indication,
		 'XOR-PEER-ADDRESS' = [PeerAddr],
		 'DATA' = Data1},
    PktOut4 = stun_codec:encode(Msg4),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut4)),
    ?assertMatch({ok, {_, _, Data1}}, gen_udp:recv(PeerSocket, 0, ?RECV_TIMEOUT)),
    %% Peer sends the data back. We receive it.
    ?assertEqual(ok, gen_udp:send(PeerSocket, RelayIP, RelayPort, Data1)),
    {ok, {_, _, Data2}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    ?assertMatch(
       {ok, #stun{'DATA' = Data1,
		  'XOR-PEER-ADDRESS' = [PeerAddr],
		  class = indication}},
       stun_codec:decode(Data2, datagram)),
    %% We're binding channel for our peer
    TrID5 = mk_trid(),
    Msg5 = #stun{method = ?STUN_METHOD_CHANNEL_BIND,
		 trid = TrID5,
		 class = request,
		 'CHANNEL-NUMBER' = ?CHANNEL,
		 'XOR-PEER-ADDRESS' = [PeerAddr],
		 'NONCE' = Nonce,
		 'REALM' = ?REALM,
		 'USERNAME' = ?USER},
    PktOut5 = stun_codec:encode(Msg5, {?USER, ?REALM, ?PASS}),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut5)),
    {ok, {_, _, PktIn5}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    ?assertMatch(
       {ok, #stun{trid = TrID5,
		  class = response}},
       stun_codec:decode(PktIn5, datagram)),
    %% Now we send data to this channel. The peer receives it.
    Data3 = crypto:rand_bytes(20),
    Msg6 = #turn{channel = ?CHANNEL, data = Data3},
    PktOut6 = stun_codec:encode(Msg6),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut6)),
    ?assertMatch({ok, {_, _, Data3}}, gen_udp:recv(PeerSocket, 0, ?RECV_TIMEOUT)),
    %% The peer sends the data back. We receive it.
    ?assertEqual(ok, gen_udp:send(PeerSocket, RelayIP, RelayPort, Data3)),
    {ok, {_, _, Data4}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    ?assertMatch(
       {ok, #turn{channel = ?CHANNEL, data = Data3}},
       stun_codec:decode(Data4, datagram)),
    %% Destroying the allocation via Refresh method (with LIFETIME set to zero)
    TrID7 = mk_trid(),
    Msg7 = #stun{method = ?STUN_METHOD_REFRESH,
		 trid = TrID7,
		 'LIFETIME' = 0,
		 'NONCE' = Nonce,
		 'REALM' = ?REALM,
		 'USERNAME' = ?USER},
    PktOut7 = stun_codec:encode(Msg7, {?USER, ?REALM, ?PASS}),
    ?assertEqual(ok, gen_udp:send(Socket, {127,0,0,1}, ?STUN_PORT, PktOut7)),
    {ok, {_, _, PktIn7}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
    ?assertMatch(
       {ok, #stun{trid = TrID7,
		  'LIFETIME' = 0,
		  class = response}},
       stun_codec:decode(PktIn7, datagram)),
    ?assertEqual(ok, gen_udp:close(PeerSocket)),
    ?assertEqual(ok, gen_udp:close(Socket)).

%%--------------------------------------------------------------------
%% External functions
%%--------------------------------------------------------------------
bind_udp(Host, Port) ->
    TrID = mk_trid(),
    MsgOut = #stun{method = ?STUN_METHOD_BINDING,
		   class = request,
		   trid = TrID},
    try
	{ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
	PktOut = stun_codec:encode(MsgOut),
	ok = gen_udp:send(Socket, Host, Port, PktOut),
	{ok, {_, _, PktIn}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
	{ok, MsgIn = #stun{trid = TrID,
			   'XOR-MAPPED-ADDRESS' = _Addr}} =
	    stun_codec:decode(PktIn, datagram),
	gen_udp:close(Socket),
	MsgIn
    catch _:{badmatch, Err} ->
	    Err
    end.

bind_tcp(Host, Port) ->
    TrID = mk_trid(),
    MsgOut = #stun{method = ?STUN_METHOD_BINDING,
		   class = request,
		   trid = TrID},
    try
	{ok, Socket} = gen_tcp:connect(Host, Port,
				       [binary, {active, false}]),
	Pkt = stun_codec:encode(MsgOut),
	ok = gen_tcp:send(Socket, Pkt),
	{ok, MsgIn = #stun{trid = TrID,
			   'XOR-MAPPED-ADDRESS' = _Addr}} =
	    recv(Socket, <<>>, false),
	gen_tcp:close(Socket),
	MsgIn
    catch _:{badmatch, Err} ->
	    Err
    end.

allocate_udp(Host, Port, User, Realm, Pass) ->
    try
	{ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
	%% Allocating address, receiving 401 with nonce and realm
	TrID1 = mk_trid(),
	Msg1 = #stun{method = ?STUN_METHOD_ALLOCATE,
		     class = request,
		     trid = TrID1},
	PktOut1 = stun_codec:encode(Msg1),
	ok = gen_udp:send(Socket, Host, Port, PktOut1),
	{ok, {_, _, PktIn1}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
	{ok, #stun{trid = TrID1,
		   class = error,
		   'ERROR-CODE' = {401, _},
		   'NONCE' = Nonce,
		   'REALM' = Realm}} = stun_codec:decode(PktIn1, datagram),
	%% Repeating allocation from the first step
	TrID2 = mk_trid(),
	Msg2 = #stun{method = ?STUN_METHOD_ALLOCATE,
		     trid = TrID2,
		     'REQUESTED-TRANSPORT' = udp,
		     'NONCE' = Nonce,
		     'REALM' = Realm,
		     'USERNAME' = User},
	PktOut2 = stun_codec:encode(Msg2, {User, Realm, Pass}),
	ok = gen_udp:send(Socket, Host, Port, PktOut2),
	{ok, {_, _, PktIn2}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
	{ok, #stun{trid = TrID2,
		   class = response,
		   'XOR-MAPPED-ADDRESS' = _Addr}} = stun_codec:decode(PktIn2, datagram),
	%% Destroying the allocation via Refresh method (with LIFETIME set to zero)
	TrID7 = mk_trid(),
	Msg7 = #stun{method = ?STUN_METHOD_REFRESH,
		     trid = TrID7,
		     'LIFETIME' = 0,
		     'NONCE' = Nonce,
		     'REALM' = Realm,
		     'USERNAME' = User},
	PktOut7 = stun_codec:encode(Msg7, {User, Realm, Pass}),
	ok = gen_udp:send(Socket, Host, Port, PktOut7),
	{ok, {_, _, PktIn7}} = gen_udp:recv(Socket, 0, ?RECV_TIMEOUT),
	{ok, #stun{trid = TrID7,
		   'LIFETIME' = 0,
		   class = response}} =
	    stun_codec:decode(PktIn7, datagram),
	gen_udp:close(Socket)
    catch _:{badmatch, Err} ->
	    Err
    end.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
recv(Socket, Buf, false) ->
    {ok, Data} = gen_tcp:recv(Socket, 0, ?RECV_TIMEOUT),
    NewBuf = <<Buf/binary, Data/binary>>,
    case stun_codec:decode(NewBuf, stream) of
	{ok, Msg, _Tail} ->
	    {ok, Msg};
	empty ->
	    recv(Socket, <<>>, false);
	more ->
	    recv(Socket, NewBuf, false)
    end;
recv(TLSSocket, Buf, true) ->
    receive
	{tcp, _Sock, TLSData} ->
	    {ok, Data} = fast_tls:recv_data(TLSSocket, TLSData),
	    NewBuf = <<Buf/binary, Data/binary>>,
	    case stun_codec:decode(NewBuf, stream) of
		{ok, Msg, _Tail} ->
		    {ok, Msg};
		empty ->
		    recv(TLSSocket, <<>>, true);
		more ->
		    recv(TLSSocket, NewBuf, true)
	    end
    after 100 ->
	    ok
    end.

mk_trid() ->
    {A, B, C} = p1_time_compat:timestamp(),
    random:seed(A, B, C),
    random:uniform(1 bsl 96).

get_cert() ->
    <<"-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJANlKDLlVYd/VMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTQwNTA2MDQ1MzUzWhcNNDEwOTIxMDQ1MzUzWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAtTUN+zzYHZxsmK3/OfAa8M8dA61k6B3pKF4FqlBFXsih0ug7HJFFSuBf
yt6mmtmNwiyYuj8Wjq+Ab97tVGscuuhrG+6tiL07L8zTUtJF9CbO9cq0+d/0axDH
AhMdxjfIhtXUNJGvjvF7gPR63nRkBFc1+K/JgJKLRRTj3pWW2LKX9DZoI+VzUFDG
Aaky1pbcTqfTy0OlPx2cGWB8/3XcNCaqdx+AgX65GJl3GaaJ8D60FtDv0Nfjnctt
/qnefYiEKFugqJz5kDGC3wiHEhlJDY5qzKcYVm3jFsOmnLDOPQ82Sb5j2ZUroxM7
lwZAnCnVVIGlXWLA5snuxxcS4LJPTQIDAQABo4GnMIGkMB0GA1UdDgQWBBT0FCNT
iq3HJPNAiOIpadSMgJU/LzB1BgNVHSMEbjBsgBT0FCNTiq3HJPNAiOIpadSMgJU/
L6FJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNV
BAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJANlKDLlVYd/VMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBABYy3wmp7MvyXM/JN5gJI39vo57XZSCa
nXV/g09z8xP5MYvdUdKLXlss1211+9GNb4l5z545HDgg55fBeHhqw5x9H/gFNM4i
ueSVWDdMaTQ7poE9u3aPeKiS+vhMvzpnFo2Ss21DznBqvWxh+4UpoT3sV9A0crV1
LP4GpbIbFJGW50UTg09NYl0qxTWU1yldrlSXZduV8+Oi4I1+KMgH3H/YD2oU8Olu
KP3TakDiw45YW43Dn5ElljXKjq7xKxbv+PRbYM3/4odQot12tdpKyI9MLJZxUXjW
VEqVAR0K1ssVEpXBE5QqD5Od5YV0zD1JTtaBqcYrqxngn8nujPgFXDo=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1NQ37PNgdnGyY
rf858Brwzx0DrWToHekoXgWqUEVeyKHS6DsckUVK4F/K3qaa2Y3CLJi6PxaOr4Bv
3u1Uaxy66Gsb7q2IvTsvzNNS0kX0Js71yrT53/RrEMcCEx3GN8iG1dQ0ka+O8XuA
9HredGQEVzX4r8mAkotFFOPelZbYspf0Nmgj5XNQUMYBqTLWltxOp9PLQ6U/HZwZ
YHz/ddw0Jqp3H4CBfrkYmXcZponwPrQW0O/Q1+Ody23+qd59iIQoW6ConPmQMYLf
CIcSGUkNjmrMpxhWbeMWw6acsM49DzZJvmPZlSujEzuXBkCcKdVUgaVdYsDmye7H
FxLgsk9NAgMBAAECggEAWeC40JZ7MyS1EH2tDBW1px9zarGETUUYsncAJFuwLLUi
3rNlLmQ3lE359Wu+AyxJDbiFAEvualNORy6xVJ/UHjjNd4tI83u4cZsMbhXxsInX
OT6TySR13OzzaGoG6JwekBJbML/Z7fKEqY+ZqeDdAvImyPSX43fMMDWOWIalzVDi
II63zd2KRklToDGfV1geEaa1NVIQucPnOQOjrID7bIDpg6UvtZkOJzZG8fhEpM19
UpYphT14UO1w8fCxSu7+V3GIDuTnYKDg98WTQejeCZk28/MIYnzAy4H5uyQFu+IJ
YieWRy2RICPTDq4OUEA9bLGgFmcvGxX2sg3elVkPgQKBgQDd6i1szwNY20iDt8P5
nn4R9E+S8iPNMswIi9PM88p5Ig44eLSRkSy3nnRdFHlu3lRvsWykKT6iTVsJCmK9
1j6FsJ9xd8ozZTdXiBRrOhNb6JjcYGWfIcsParAth/P+luFv9VhKMjuqNjRNAWwn
0zeT6+HQ8W2IN4sLSRDxaiLUPQKBgQDRCjuyaneYKrDjoRk4lNu+krIK6q05V87V
96gm4qIUKZvnCN7tqCC1ETVzKyhsQfRUvrQi3U0yhV018Um7hQdLZFCwJ/Ku8F2v
2OD2mNBLeRtKjwSoDXxqfEAJ0sZJS1xXHF13HR7g0LVjJzHheyHfhmat4QJEXp+6
JVuC86xIUQKBgFbiR9SxHFNez35apY0G478t0zXqPeAqQj4aWNuGm8BfeAfeInxX
xZVCobaLvJuOyqpMYgfH6jDrbngUq+I9jo8TPunTB8SlnUxVCAGPZGL4p1ipGUB7
n6AymjXJY9tKwYrvGRk7n6adwE5h/zF8fecZVHlU/Rh2/qZ1ff+3GVnVAoGALYuE
PDhUPFQ43C+ydhCA3EHMBvLgsRi/mQDvoyFH3Qq/zBOztqYmEi1gruodUZEBMiGm
z93Vvwctqt4aiX/Peg6uQeNCTflTAEhJo5Dh+T+2wYTtp8vgarcNoNZKm5eO0+/7
MUOoAaWXj7XveUhBthjrcEERJGJVfNI84QhEZjECgYEAgFga2Cw7LxZ9Sc8I+a5O
7nLykkHLOq1fMs2byjX2A7LcxPuq0ebSiFWQ/0avbS8QoTMSJLrFCnt9DJ8JDxX4
j7iD63xhs0Ue1eW2l2QX5q9iCUXfcjsSo6FJ5wFqp4GYkMMsoP99/toEifz9qxLN
ySqCx+ihshDA0yipJbUuU2c=
-----END PRIVATE KEY-----">>.
