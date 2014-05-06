%%%-------------------------------------------------------------------
%%% File    : stun_test.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : STUN test suite
%%% Created :  7 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% ejabberd, Copyright (C) 2002-2010   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%-------------------------------------------------------------------
-module(stun_test).

-define(STUN_PORT, 34780).
-define(STUNS_PORT, 53490).
-define(RECV_TIMEOUT, timer:seconds(5)).

-include_lib("eunit/include/eunit.hrl").
-include("stun.hrl").

init_test() ->
    ?assertEqual(ok, application:start(p1_tls)),
    ?assertEqual(ok, application:start(p1_stun)).

mk_cert_test() ->
    ?assertEqual(ok, file:write_file("certfile.pem", get_cert())).

add_udp_listener_test() ->
    ?assertEqual(ok, stun_listener:add_listener(?STUN_PORT, udp, [])).

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
       stun_codec:decode(PktIn, datagram)).

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
       recv(Socket, <<>>, false)).

bind_tls_test() ->
    TrID = mk_trid(),
    Msg = #stun{method = ?STUN_METHOD_BINDING,
 		class = request,
 		trid = TrID},
    {ok, Socket} = gen_tcp:connect({127,0,0,1}, ?STUNS_PORT,
				   [binary, {active, true}]),
    {ok, TLSSocket} = p1_tls:tcp_to_tls(
			Socket, [{certfile, <<"certfile.pem">>}, connect]),
    ?assertEqual({ok, <<>>}, p1_tls:recv_data(TLSSocket, <<>>)),
    {ok, Addr} = p1_tls:sockname(TLSSocket),
    Pkt = stun_codec:encode(Msg),
    recv(TLSSocket, <<>>, true),
    ?assertEqual(ok, p1_tls:send(TLSSocket, Pkt)),
    ?assertMatch(
       {ok, #stun{trid = TrID,
		  'XOR-MAPPED-ADDRESS' = Addr}},
       recv(TLSSocket, <<>>, true)).

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
	    {ok, Data} = p1_tls:recv_data(TLSSocket, TLSData),
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
    {A, B, C} = now(),
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
