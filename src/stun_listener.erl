%%%----------------------------------------------------------------------
%%% File    : stun_listener.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Purpose : 
%%% Created : 9 Jan 2011 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2022 ProcessOne, SARL. All Rights Reserved.
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

-module(stun_listener).

-behaviour(gen_server).

%% API
-export([start_link/0, add_listener/4, del_listener/3, start_listener/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include("stun_logger.hrl").

-define(TCP_SEND_TIMEOUT, 10000).
-define(UDP_READ_PACKETS, 100).
-define(UDP_RECBUF, 1024 * 1024). % 1 MiB
-record(state, {listeners = #{}}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

add_listener(IP, Port, Transport, Opts) ->
    gen_server:call(?MODULE, {add_listener, IP, Port, Transport, Opts}).

del_listener(IP, Port, Transport) ->
    gen_server:call(?MODULE, {del_listener, IP, Port, Transport}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    {ok, #state{}}.

handle_call({add_listener, IP, Port, Transport, Opts}, _From, State) ->
    case maps:find({IP, Port, Transport}, State#state.listeners) of
	{ok, _} ->
	    Err = {error, already_started},
	    {reply, Err, State};
	error ->
	    {Pid, MRef} = spawn_monitor(?MODULE, start_listener,
					[IP, Port, Transport, Opts, self()]),
	    receive
		{'DOWN', MRef, _Type, _Object, Info} ->
		    Res = {error, Info},
		    format_listener_error(IP, Port, Transport, Opts, Res),
		    {reply, Res, State};
		{Pid, Reply} ->
		    case Reply of
			{error, _} = Err ->
			    format_listener_error(IP, Port, Transport, Opts,
						  Err),
			    {reply, Reply, State};
			ok ->
			    Listeners = maps:put(
					  {IP, Port, Transport},
					  {MRef, Pid, Opts},
					  State#state.listeners),
			    {reply, ok, State#state{listeners = Listeners}}
		    end
	    end
    end;
handle_call({del_listener, IP, Port, Transport}, _From, State) ->
    case maps:find({IP, Port, Transport}, State#state.listeners) of
	{ok, {MRef, Pid, _Opts}} ->
	    catch erlang:demonitor(MRef, [flush]),
	    catch exit(Pid, kill),
	    Listeners = maps:remove({IP, Port, Transport},
				    State#state.listeners),
	    {reply, ok, State#state{listeners = Listeners}};
	error ->
	    {reply, {error, notfound}, State}
    end;
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MRef, _Type, _Pid, Info}, State) ->
    Listeners = maps:filter(
		  fun({IP, Port, Transport}, {Ref, _, _}) when Ref == MRef ->
			  ?LOG_ERROR("Listener on ~s (~s) failed: ~p",
				     [stun_logger:encode_addr({IP, Port}),
				      Transport, Info]),
			  false;
		     (_, _) ->
			  true
		  end, State#state.listeners),
    {noreply, State#state{listeners = Listeners}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
start_listener(IP, Port, Transport0, Opts0, Owner)
  when Transport0 == tcp;
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
	    Owner ! {self(), ok},
	    Opts1 = stun:tcp_init(ListenSocket, Opts),
	    accept(Transport, ListenSocket, Opts1);
	Err ->
	    Owner ! {self(), Err}
    end;
start_listener(IP, Port, udp, Opts, Owner) ->
    case gen_udp:open(Port, [binary,
			     {ip, IP},
			     {active, false},
			     {recbuf, ?UDP_RECBUF},
			     {read_packets, ?UDP_READ_PACKETS},
			     {reuseaddr, true}]) of
	{ok, Socket} ->
	    Owner ! {self(), ok},
	    stun_logger:set_metadata(listener, udp),
	    Opts1 = stun:udp_init(Socket, Opts),
	    udp_recv(Socket, Opts1);
	Err ->
	    Owner ! {self(), Err}
    end.

-ifdef(USE_OLD_INET_BACKEND).
listen(_Transport, Port, Opts) ->
    gen_tcp:listen(Port, Opts).
-else.
listen(auto, Port, Opts) ->
    gen_tcp:listen(Port, [{inet_backend, socket} | Opts]);
listen(_Transport, Port, Opts) ->
    gen_tcp:listen(Port, Opts).
-endif.

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
	{error, Reason} ->
	    ?LOG_ERROR("Unexpected UDP error: ~s", [inet:format_error(Reason)]),
	    erlang:error(Reason)
    end.

format_listener_error(IP, Port, Transport, Opts, Err) ->
    ?LOG_ERROR("Cannot start listener:~n"
	       "** IP: ~s~n"
	       "** Port: ~B~n"
	       "** Transport: ~s~n"
	       "** Options: ~p~n"
	       "** Reason: ~p",
	       [stun_logger:encode_addr(IP), Port,
		stun_logger:encode_transport(Transport), Opts, Err]).
