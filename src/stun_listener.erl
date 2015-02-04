%%%----------------------------------------------------------------------
%%% File    : stun_listener.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Purpose : 
%%% Created : 9 Jan 2011 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% stun, Copyright (C) 2002-2015   ProcessOne
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
%%%----------------------------------------------------------------------

-module(stun_listener).

-behaviour(gen_server).

%% API
-export([start_link/0, add_listener/3, del_listener/2, start_listener/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(TCP_SEND_TIMEOUT, 10000).
-record(state, {listeners = dict:new() :: dict()}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

add_listener(Port, Transport, Opts) ->
    gen_server:call(?MODULE, {add_listener, Port, Transport, Opts}).

del_listener(Port, Transport) ->
    gen_server:call(?MODULE, {del_listener, Port, Transport}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    {ok, #state{}}.

handle_call({add_listener, Port, Transport, Opts}, _From, State) ->
    case dict:find({Port, Transport}, State#state.listeners) of
	{ok, _} ->
	    Err = {error, already_started},
	    {reply, Err, State};
	error ->
	    {Pid, MRef} = spawn_monitor(?MODULE, start_listener,
					[Port, Transport, Opts, self()]),
	    receive
		{'DOWN', MRef, _Type, _Object, Info} ->
		    Res = {error, Info},
		    format_listener_error(Port, Transport, Opts, Res),
		    {reply, Res, State};
		{Pid, Reply} ->
		    case Reply of
			{error, _} = Err ->
			    format_listener_error(Port, Transport, Opts, Err),
			    {reply, Reply, State};
			ok ->
			    Listeners = dict:store(
					  {Port, Transport}, {MRef, Pid, Opts},
					  State#state.listeners),
			    {reply, ok, State#state{listeners = Listeners}}
		    end
	    end
    end;
handle_call({del_listener, Port, Transport}, _From, State) ->
    case dict:find({Port, Transport}, State#state.listeners) of
	{ok, {MRef, Pid, _Opts}} ->
	    catch erlang:demonitor(MRef, [flush]),
	    catch exit(Pid, kill),
	    Listeners = dict:erase({Port, Transport}, State#state.listeners),
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
    Listeners = dict:filter(
		  fun({Port, Transport}, {Ref, _, _}) when Ref == MRef ->
			  error_logger:error_msg("listener on ~p/~p failed: ~p",
						 [Port, Transport, Info]),
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
start_listener(Port, Transport, Opts, Owner)
  when Transport == tcp; Transport == tls ->
    OptsWithTLS = case Transport of
		      tls -> [tls|Opts];
		      tcp -> Opts
		  end,
    case gen_tcp:listen(Port, [binary,
                               {packet, 0},
                               {active, false},
                               {reuseaddr, true},
                               {nodelay, true},
                               {keepalive, true},
			       {send_timeout, ?TCP_SEND_TIMEOUT},
			       {send_timeout_close, true}]) of
        {ok, ListenSocket} ->
            Owner ! {self(), ok},
	    OptsWithTLS1 = stun:tcp_init(ListenSocket, OptsWithTLS),
            accept(ListenSocket, OptsWithTLS1);
        Err ->
            Owner ! {self(), Err}
    end;
start_listener(Port, udp, Opts, Owner) ->
    case gen_udp:open(Port, [binary,
			     {active, false},
			     {reuseaddr, true}]) of
	{ok, Socket} ->
	    Owner ! {self(), ok},
	    Opts1 = stun:udp_init(Socket, Opts),
	    udp_recv(Socket, Opts1);
	Err ->
	    Owner ! {self(), Err}
    end.

accept(ListenSocket, Opts) ->
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            case {inet:peername(Socket),
                  inet:sockname(Socket)} of
                {{ok, {PeerAddr, PeerPort}}, {ok, {Addr, Port}}} ->
                    error_logger:info_msg("accepted connection: ~s:~p -> ~s:~p",
					  [inet_parse:ntoa(PeerAddr), PeerPort,
					   inet_parse:ntoa(Addr), Port]),
                    case stun:start({gen_tcp, Socket}, Opts) of
                        {ok, Pid} ->
                            gen_tcp:controlling_process(Socket, Pid);
                        Err ->
                            Err
                    end;
                Err ->
                    error_logger:error_msg("unable to fetch peername: ~p", [Err]),
                    Err
            end,
            accept(ListenSocket, Opts);
        Err ->
            Err
    end.

udp_recv(Socket, Opts) ->
    case gen_udp:recv(Socket, 0) of
	{ok, {Addr, Port, Packet}} ->
	    case catch stun:udp_recv(Socket, Addr, Port, Packet, Opts) of
		{'EXIT', Reason} ->
		    error_logger:error_msg("failed to process UDP packet:~n"
					   "** Source: {~p, ~p}~n"
					   "** Reason: ~p~n** Packet: ~p",
					   [Addr, Port, Reason, Packet]),
		    udp_recv(Socket, Opts);
		NewOpts ->
		    udp_recv(Socket, NewOpts)
	    end;
	{error, Reason} ->
	    error_logger:error_msg(
	      "unexpected UDP error: ~s", [inet:format_error(Reason)]),
	    erlang:error(Reason)
    end.

format_listener_error(Port, Transport, Opts, Err) ->
    error_logger:error_msg("failed to start listener:~n"
			   "** Port: ~p~n"
			   "** Transport: ~p~n"
			   "** Options: ~p~n"
			   "** Reason: ~p",
			   [Port, Transport, Opts, Err]).
