%%%-------------------------------------------------------------------
%%% File    : stun.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : RFC5389 implementation.
%%%               Currently only Binding usage is supported.
%%%
%%% Created :  8 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% stun, Copyright (C) 2002-2013   ProcessOne
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
-module(stun).

-behaviour(gen_fsm).

%% API
-export([start_link/2, start/2, socket_type/0,
	 udp_recv/5]).

%% gen_fsm callbacks
-export([init/1, handle_event/3, handle_sync_event/4,
	 handle_info/3, terminate/3, code_change/4]).

%% gen_fsm states
-export([wait_for_tls/2, session_established/2]).

-include("stun.hrl").

-define(MAX_BUF_SIZE, 64 * 1024).

-define(TIMEOUT, 10000).

-define(DEFAULT_SERVER_NAME, <<"Erlang STUN library">>).

-type option() :: {certfile, iodata()} | {server_name, iodata()}.
-type options() :: [option()].

-record(state,
	{sock                  :: inet:socket() | p1_tls:tls_socket(),
         sock_mod = gen_tcp    :: gen_udp | gen_tcp | p1_tls,
         certfile              :: iodata(),
         server_name           :: iodata(),
         peer = {{0,0,0,0}, 0} :: {inet:ip_address(), inet:port_number()},
         tref = make_ref()     :: reference(),
	 buf = <<>>            :: binary()}).

-spec start({gen_tcp, inet:socket()}, options()) ->
                   {ok, supervisor:child()} |
                   {ok, supervisor:child(), term()} |
                   {error,
                    already_present |
                    {already_started, supervisor:child()} |
                    term()}.

%% @doc Start the STUN process serving TCP connection and attach it to the
%% supervisor `stun_sup'.
%% @end.
start({gen_tcp, Sock}, Opts) ->
    supervisor:start_child(stun_sup, [Sock, Opts]).

-spec start_link(inet:socket(), options()) ->
                        {ok, pid()} |
                        ignore |
                        {error, {already_started, pid()} | term()}.

%% @hidden
start_link(Sock, Opts) ->
    gen_fsm:start_link(?MODULE, [Sock, Opts], []).

%% @private
socket_type() -> raw.

-spec udp_recv(inet:socket(), inet:ip_address(), inet:port_number(),
               iodata(), options()) -> ok.

%% @doc Process the STUN message received via UDP socket `Sock'
%% from address `Addr' and port `Port'.
%% @end
udp_recv(Sock, Addr, Port, Data, Opts) ->
    case stun_codec:decode(Data) of
      {ok, Msg, <<>>} ->
	  case process(Addr, Port, Msg, Opts) of
	    RespMsg when is_record(RespMsg, stun) ->
		Data1 = stun_codec:encode(RespMsg),
		gen_udp:send(Sock, Addr, Port, Data1);
	    _ -> ok
	  end;
      _ -> ok
    end.

%% @private
init([Sock, Opts]) ->
    case inet:peername(Sock) of
      {ok, Addr} ->
	  inet:setopts(Sock, [{active, once}]),
	  TRef = erlang:start_timer(?TIMEOUT, self(), stop),
	  State = #state{sock = Sock, peer = Addr, tref = TRef},
          ServerName = proplists:get_value(
                         server_name, Opts, ?DEFAULT_SERVER_NAME),
	  case proplists:get_value(certfile, Opts) of
	    undefined -> {ok, session_established, State};
	    CertFile ->
		{ok, wait_for_tls, State#state{certfile = CertFile,
                                               server_name = ServerName}}
	  end;
      Err -> Err
    end.

%% @private
wait_for_tls(Event, State) ->
    error_logger:error_msg("unexpected event in wait_for_tls: ~p~n",
                           [Event]),
    {next_state, wait_for_tls, State}.

%% @private
session_established(Msg, State)
    when is_record(Msg, stun) ->
    {Addr, Port} = State#state.peer,
    case process(Addr, Port, Msg,
                 [{server_name, State#state.server_name}]) of
      Resp when is_record(Resp, stun) ->
	  Data = stun_codec:encode(Resp),
	  (State#state.sock_mod):send(State#state.sock, Data);
      _ -> ok
    end,
    {next_state, session_established, State};
session_established(Event, State) ->
    error_logger:error_msg("unexpected event in session_established: ~p~n",
                           [Event]),
    {next_state, session_established, State}.

%% @private
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

%% @private
handle_sync_event(_Event, _From, StateName, State) ->
    {reply, {error, badarg}, StateName, State}.

%% @private
handle_info({tcp, Sock, TLSData}, wait_for_tls,
	    State) ->
    Buf = <<(State#state.buf)/binary, TLSData/binary>>,
    case Buf of
      _ when byte_size(Buf) < 3 ->
	  {next_state, wait_for_tls,
	   update_state(State#state{buf = Buf})};
      <<_:16, 1, _/binary>> ->
	  TLSOpts = [{certfile, State#state.certfile}],
	  {ok, TLSSock} = p1_tls:tcp_to_tls(Sock, TLSOpts),
	  NewState = State#state{sock = TLSSock, buf = <<>>,
				 sock_mod = p1_tls},
	  case p1_tls:recv_data(TLSSock, Buf) of
	    {ok, Data} ->
		process_data(session_established, NewState, Data);
	    _Err -> {stop, normal, NewState}
	  end;
      _ -> process_data(session_established, State, TLSData)
    end;
handle_info({tcp, _Sock, TLSData}, StateName,
	    #state{sock_mod = p1_tls} = State) ->
    case p1_tls:recv_data(State#state.sock, TLSData) of
      {ok, Data} -> process_data(StateName, State, Data);
      _Err -> {stop, normal, State}
    end;
handle_info({tcp, _Sock, Data}, StateName, State) ->
    process_data(StateName, State, Data);
handle_info({tcp_closed, _Sock}, _StateName, State) ->
    {stop, normal, State};
handle_info({tcp_error, _Sock, _Reason}, _StateName,
	    State) ->
    {stop, normal, State};
handle_info({timeout, TRef, stop}, _StateName,
	    #state{tref = TRef} = State) ->
    {stop, normal, State};
handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.

%% @private
terminate(_Reason, _StateName, State) ->
    catch (State#state.sock_mod):close(State#state.sock),
    ok.

%% @private
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% @private
process(Addr, Port,
	#stun{class = request, unsupported = []} = Msg, Opts) ->
    Resp = prepare_response(Msg, Opts),
    if Msg#stun.method == (?STUN_METHOD_BINDING) ->
	   case stun_codec:version(Msg) of
	     old ->
		 Resp#stun{class = response,
			   'MAPPED-ADDRESS' = {Addr, Port}};
	     new ->
		 Resp#stun{class = response,
			   'XOR-MAPPED-ADDRESS' = {Addr, Port}}
	   end;
       true ->
	   Resp#stun{class = error,
		     'ERROR-CODE' = {405, <<"Method Not Allowed">>}}
    end;
process(_Addr, _Port, #stun{class = request} = Msg, Opts) ->
    Resp = prepare_response(Msg, Opts),
    Resp#stun{class = error,
	      'UNKNOWN-ATTRIBUTES' = Msg#stun.unsupported,
	      'ERROR-CODE' = {420, stun_codec:reason(420)}};
process(_Addr, _Port, _Msg, _Opts) -> pass.

%% @private
prepare_response(Msg, Opts) ->
    Version = proplists:get_value(server_name, Opts, <<"Erlang STUN library">>),
    #stun{method = Msg#stun.method, magic = Msg#stun.magic,
	  trid = Msg#stun.trid, 'SOFTWARE' = Version}.

%% @private
process_data(NextStateName, #state{buf = Buf} = State,
	     Data) ->
    NewBuf = <<Buf/binary, Data/binary>>,
    case stun_codec:decode(NewBuf) of
      {ok, Msg, Tail} ->
	  gen_fsm:send_event(self(), Msg),
	  process_data(NextStateName, State#state{buf = <<>>},
		       Tail);
      empty ->
	  NewState = State#state{buf = <<>>},
	  {next_state, NextStateName, update_state(NewState)};
      more when byte_size(NewBuf) < (?MAX_BUF_SIZE) ->
	  NewState = State#state{buf = NewBuf},
	  {next_state, NextStateName, update_state(NewState)};
      _ -> {stop, normal, State}
    end.

%% @private
update_state(#state{sock = Sock} = State) ->
    case State#state.sock_mod of
      gen_tcp -> inet:setopts(Sock, [{active, once}]);
      SockMod -> SockMod:setopts(Sock, [{active, once}])
    end,
    cancel_timer(State#state.tref),
    TRef = erlang:start_timer(?TIMEOUT, self(), stop),
    State#state{tref = TRef}.

%% @private
cancel_timer(TRef) ->
    case erlang:cancel_timer(TRef) of
      false ->
	  receive {timeout, TRef, _} -> ok after 0 -> ok end;
      _ -> ok
    end.
