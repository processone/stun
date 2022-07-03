%%%----------------------------------------------------------------------
%%% File    : stun_acceptor.erl
%%% Author  : Holger Weiss <holger@zedat.fu-berlin.de>
%%% Purpose : STUN/TURN acceptor
%%% Created :  3 Jul 2022 by Holger Weiss <holger@zedat.fu-berlin.de>
%%%
%%%
%%% Copyright (C) 2022 ProcessOne, SARL. All Rights Reserved.
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
%%%----------------------------------------------------------------------

-module(stun_acceptor).
-author('holger@zedat.fu-berlin.de').
-export([start_link/4]).
-export([init/4]).

-include("stun_logger.hrl").

-define(TCP_SEND_TIMEOUT, 10000).
-define(UDP_READ_PACKETS, 100).
-define(UDP_RECBUF, 1024 * 1024). % 1 MiB

-type ip() :: inet:ip_address().
-type port_number() :: inet:port_number().
-type udp_socket() :: gen_udp:socket().
-type tcp_socket() :: gen_tcp:socket().
-type transport() :: udp | tcp | tls | auto.
-type opts() :: proplist:proplist().

%% API.

-spec start_link(ip(), port_number(), transport(), opts())
      -> {ok, pid()} | {error, term()}.
start_link(IP, Port, Transport, Opts) ->
    proc_lib:start_link(?MODULE, init, [IP, Port, Transport, Opts]).

-spec init(ip(), port_number(), transport(), opts()) -> no_return().
init(IP, Port, Transport0, Opts0) when Transport0 == tcp;
				       Transport0 == tls;
				       Transport0 == auto ->
    {Transport, Opts} = case {Transport0, proplists:get_value(tls, Opts0)} of
			    {tcp, false} ->
				{tcp, Opts0};
			    {tcp, true} ->
				{tls, Opts0};
			    {tcp, optional} ->
				{auto, Opts0};
			    {tls, undefined} ->
				{tls, [tls | Opts0]};
			    {auto, undefined} ->
				{auto, [{tls, optional} | Opts0]};
			    {_Transport, _TLS} ->
				{Transport0, Opts0}
			end,
    case listen(Transport, Port, [binary,
				  {ip, IP},
				  {packet, 0},
				  {active, false},
				  {reuseaddr, true},
				  {nodelay, true},
				  {keepalive, true},
				  {send_timeout, ?TCP_SEND_TIMEOUT},
				  {send_timeout_close, true}]) of
	{ok, ListenSocket} ->
	    Opts1 = stun:tcp_init(ListenSocket, Opts),
	    proc_lib:init_ack({ok, self()}),
	    accept(Transport, ListenSocket, Opts1);
	{error, Reason} ->
	    log_error(IP, Port, Transport, Opts, Reason),
	    exit(Reason)
    end;
init(IP, Port, udp, Opts) ->
    case gen_udp:open(Port, [binary,
			     {ip, IP},
			     {active, false},
			     {recbuf, ?UDP_RECBUF},
			     {read_packets, ?UDP_READ_PACKETS},
			     {reuseaddr, true}]) of
	{ok, Socket} ->
	    stun_logger:set_metadata(listener, udp),
	    Opts1 = stun:udp_init(Socket, Opts),
	    proc_lib:init_ack({ok, self()}),
	    udp_recv(Socket, Opts1);
	{error, Reason} ->
	    log_error(IP, Port, udp, Opts, Reason),
	    exit(Reason)
    end.

%% Internal functions.

-spec listen(transport(), port_number(), opts())
      -> {ok, tcp_socket()} | {error, term()}.
-ifdef(USE_OLD_INET_BACKEND).
listen(_Transport, Port, Opts) ->
    gen_tcp:listen(Port, Opts).
-else.
listen(auto, Port, Opts) ->
    gen_tcp:listen(Port, [{inet_backend, socket} | Opts]);
listen(_Transport, Port, Opts) ->
    gen_tcp:listen(Port, Opts).
-endif.

-spec accept(transport(), tcp_socket(), opts()) -> no_return().
accept(Transport, ListenSocket, Opts) ->
    Proxy = proplists:get_bool(proxy_protocol, Opts),
    ID = stun_logger:make_id(),
    Opts1 = [{session_id, ID} | Opts],
    stun_logger:set_metadata(listener, Transport, ID),
    case gen_tcp:accept(ListenSocket) of
	{ok, Socket} when Proxy ->
	    case p1_proxy_protocol:decode(gen_tcp, Socket, 10000) of
		{{Addr, Port}, {PeerAddr, PeerPort}} = SP ->
		    Opts2 = [{sock_peer_name, SP} | Opts1],
		    ?LOG_INFO("Accepting proxied connection: ~s -> ~s",
			      [stun_logger:encode_addr({PeerAddr, PeerPort}),
			       stun_logger:encode_addr({Addr, Port})]),
		    case stun:start({gen_tcp, Socket}, Opts2) of
			{ok, Pid} ->
			    gen_tcp:controlling_process(Socket, Pid);
			{error, Reason} ->
			    ?LOG_ERROR("Cannot start connection: ~s", [Reason]),
			    gen_tcp:close(Socket)
		    end;
		{error, Reason} ->
		    ?LOG_ERROR("Cannot parse proxy protocol: ~s",
			       [inet:format_error(Reason)]),
		    gen_tcp:close(Socket);
		{undefined, undefined} ->
		    ?LOG_ERROR("Cannot parse proxy protocol: unknown protocol"),
		    gen_tcp:close(Socket)
	    end;
	{ok, Socket} ->
	    case {inet:peername(Socket),
		  inet:sockname(Socket)} of
		{{ok, {PeerAddr, PeerPort}}, {ok, {Addr, Port}}} ->
		    ?LOG_INFO("Accepting connection: ~s -> ~s",
			      [stun_logger:encode_addr({PeerAddr, PeerPort}),
			       stun_logger:encode_addr({Addr, Port})]),
		    case stun:start({gen_tcp, Socket}, Opts1) of
			{ok, Pid} ->
			    gen_tcp:controlling_process(Socket, Pid);
			{error, Reason} ->
			    ?LOG_ERROR("Cannot start connection: ~s", [Reason]),
			    gen_tcp:close(Socket)
		    end;
		Err ->
		    ?LOG_ERROR("Cannot fetch peername: ~p", [Err]),
		    gen_tcp:close(Socket)
	    end;
	{error, Reason} ->
	    ?LOG_ERROR("Cannot accept connection: ~s", [Reason])
    end,
    accept(Transport, ListenSocket, Opts).

-spec udp_recv(udp_socket(), opts()) -> no_return().
udp_recv(Socket, Opts) ->
    case gen_udp:recv(Socket, 0) of
	{ok, {Addr, Port, Packet}} ->
	    case catch stun:udp_recv(Socket, Addr, Port, Packet, Opts) of
		{'EXIT', Reason} ->
		    ?LOG_ERROR("Cannot process UDP packet:~n"
			       "** Source: ~s~n"
			       "** Reason: ~p~n** Packet: ~p",
			       [stun_logger:encode_addr({Addr, Port}), Reason,
				Packet]),
		    udp_recv(Socket, Opts);
		NewOpts ->
		    udp_recv(Socket, NewOpts)
	    end;
	{error, Reason = econnreset} ->
	    ?LOG_INFO("Cannot receive UDP packet: ~s",
		      [inet:format_error(Reason)]),
	    udp_recv(Socket, Opts);
	{error, Reason} ->
	    ?LOG_ERROR("Unexpected UDP error: ~s", [inet:format_error(Reason)]),
	    erlang:error(Reason)
    end.

-spec log_error(ip(), port_number(), transport(), opts(), term()) -> any().
log_error(IP, Port, Transport, Opts, Reason) ->
    ?LOG_ERROR("Cannot start listener:~n"
	       "** IP: ~s~n"
	       "** Port: ~B~n"
	       "** Transport: ~s~n"
	       "** Options: ~p~n"
	       "** Reason: ~s",
	       [stun_logger:encode_addr(IP), Port,
		stun_logger:encode_transport(Transport), Opts,
		inet:format_error(Reason)]).
