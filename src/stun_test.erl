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

-compile(export_all).

-include("stun.hrl").

%%====================================================================
%% API
%%====================================================================
bind_msg() ->
    Msg = #stun{method = ?STUN_METHOD_BINDING,
		class = request,
		trid = random:uniform(1 bsl 96),
		'SOFTWARE' = <<"test">>},
    stun_codec:encode(Msg).

test_udp(Addr, Port) ->
    test(Addr, Port, gen_udp).

test_tcp(Addr, Port) ->
    test(Addr, Port, gen_tcp).

test_tls(Addr, Port) ->
    test(Addr, Port, ssl).

test(Addr, Port, Mod) ->
    Res = case Mod of
	      gen_udp ->
		  Mod:open(0, [binary, {active, false}]);
	      _ ->
		  Mod:connect(Addr, Port,
			      [binary, {active, false}], 1000)
	  end,
    case Res of
	{ok, Sock} ->
	    if Mod == gen_udp ->
		    Mod:send(Sock, Addr, Port, bind_msg());
	       true ->
		    Mod:send(Sock, bind_msg())
	    end,
	    case Mod:recv(Sock, 0, 1000) of
		{ok, {_, _, Data}} ->
		    try_dec(Data, datagram);
		{ok, Data} ->
		    try_dec(Data, stream);
		Err ->
		    io:format("err: ~p~n", [Err])
	    end,
	    Mod:close(Sock);
	Err ->
	    io:format("err: ~p~n", [Err])
    end.

try_dec(Data, Type) ->
    case stun_codec:decode(Data, Type) of
	{ok, Msg} ->
	    io:format("got:~n~s~n", [stun_codec:pp(Msg)]);
	{ok, Msg, _} ->
	    io:format("got:~n~s~n", [stun_codec:pp(Msg)]);
	Err ->
	    io:format("err: ~p~n", [Err])
    end.

public_servers() ->
    [{"stun.ekiga.net", 3478, 3478, 5349},
     {"stun.fwdnet.net", 3478, 3478, 5349},
     {"stun.ideasip.com", 3478, 3478, 5349},
     {"stun01.sipphone.com", 3478, 3478, 5349},
     {"stun.softjoys.com", 3478, 3478, 5349},
     {"stun.voipbuster.com", 3478, 3478, 5349},
     {"stun.voxgratia.org", 3478, 3478, 5349},
     {"stun.xten.com", 3478, 3478, 5349},
     {"stunserver.org", 3478, 3478, 5349},
     {"stun.sipgate.net", 10000, 10000, 5349},
     {"numb.viagenie.ca", 3478, 3478, 5349},
     {"stun.ipshka.com", 3478, 3478, 5349},
     {"localhost", 3478, 5349, 5349}].

test_public() ->
    ssl:start(),
    lists:foreach(
      fun({Addr, UDPPort, TCPPort, TLSPort}) ->
	      io:format("trying ~s:~p on UDP... ", [Addr, UDPPort]),
	      test_udp(Addr, UDPPort),
	      io:format("trying ~s:~p on TCP... ", [Addr, TCPPort]),
	      test_tcp(Addr, TCPPort),
	      io:format("trying ~s:~p on TLS... ", [Addr, TLSPort]),
	      test_tls(Addr, TLSPort)
      end, public_servers()).
