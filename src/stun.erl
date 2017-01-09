%%%-------------------------------------------------------------------
%%% File    : stun.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : RFC5389/RFC5766 implementation.
%%% Created :  8 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
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

-module(stun).

-define(GEN_FSM, gen_fsm).
-behaviour(?GEN_FSM).

%% API
-export([start_link/2,
	 start/2,
	 stop/1,
	 socket_type/0,
	 tcp_init/2,
	 udp_init/2,
	 udp_recv/5]).

%% gen_fsm callbacks
-export([init/1,
	 handle_event/3,
	 handle_sync_event/4,
	 handle_info/3,
	 terminate/3,
	 code_change/4]).

%% gen_fsm states
-export([session_established/2]).

-include("stun.hrl").

-define(MAX_BUF_SIZE, 64*1024). %% 64kb
-define(TIMEOUT, 60000). %% 1 minute
-define(NONCE_LIFETIME, 60*1000*1000). %% 1 minute (in usec)
-define(SERVER_NAME, <<"P1 STUN library">>).

%%-define(debug, true).
-ifdef(debug).
-define(dbg(Str, Args), error_logger:info_msg(Str, Args)).
-else.
-define(dbg(Str, Args), ok).
-endif.

-type addr() :: {inet:ip_address(), inet:port_number()}.

-record(state,
	{sock                        :: inet:socket() | fast_tls:tls_socket(),
	 sock_mod = gen_tcp          :: gen_udp | gen_tcp | fast_tls,
	 certfile                    :: iodata(),
	 peer = {{0,0,0,0}, 0}       :: addr(),
	 tref = make_ref()           :: reference(),
	 use_turn = false            :: boolean(),
	 relay_ip = {127,0,0,1}      :: inet:ip_address(),
	 min_port = 49152            :: non_neg_integer(),
	 max_port = 65535            :: non_neg_integer(),
	 max_allocs = 10             :: non_neg_integer() | infinity,
	 shaper = none               :: stun_shaper:shaper(),
	 max_permissions = 10        :: non_neg_integer() | infinity,
	 auth = user                 :: anonymous | user,
	 nonces = treap:empty()      :: treap:treap(),
	 realm = <<"">>              :: binary(),
	 auth_fun                    :: function(),
	 server_name = ?SERVER_NAME  :: binary(),
	 buf = <<>>                  :: binary()}).

%%====================================================================
%% API
%%====================================================================
start({gen_tcp, Sock}, Opts) ->
    supervisor:start_child(stun_tmp_sup, [Sock, Opts]).

stop(Pid) ->
    ?GEN_FSM:send_all_state_event(Pid, stop).

start_link(Sock, Opts) ->
    ?GEN_FSM:start_link(?MODULE, [Sock, Opts], []).

socket_type() ->
    raw.

tcp_init(_Sock, Opts) ->
    Opts.

udp_init(Sock, Opts) ->
    seed(),
    prepare_state(Opts, Sock, {{0,0,0,0}, 0}, gen_udp).

udp_recv(Sock, Addr, Port, Data, State) ->
    NewState = prepare_state(State, Sock, {Addr, Port}, gen_udp),
    case stun_codec:decode(Data, datagram) of
 	{ok, Msg} ->
 	    ?dbg("got: ~s", [stun_codec:pp(Msg)]),
 	    process(NewState, Msg);
 	_ ->
	    NewState
    end.

%%====================================================================
%% gen_fsm callbacks
%%====================================================================
init([Sock, Opts]) ->
    case inet:peername(Sock) of
	{ok, Addr} ->
	    seed(),
	    TRef = erlang:start_timer(?TIMEOUT, self(), stop),
	    SockMod = get_sockmod(Opts),
	    State = prepare_state(Opts, Sock, Addr, SockMod),
	    CertFile = get_certfile(Opts),
	    case maybe_starttls(Sock, SockMod, CertFile, Addr) of
		{ok, NewSock} ->
		    inet:setopts(Sock, [{active, once}]),
		    {ok, session_established,
		     State#state{tref = TRef, sock = NewSock}};
		{error, Why} ->
		    {stop, Why}
	    end;
	Err ->
	    Err
    end.

session_established(Event, State) ->
    error_logger:error_msg("unexpected event in session_established: ~p", [Event]),
    {next_state, session_established, State}.

handle_event(stop, _StateName, State) ->
    {stop, normal, State};
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {reply, {error, badarg}, StateName, State}.

handle_info({tcp, _Sock, TLSData}, StateName,
	    #state{sock_mod = fast_tls} = State) ->
    NewState = update_shaper(State, TLSData),
    case fast_tls:recv_data(NewState#state.sock, TLSData) of
	{ok, Data} ->
	    process_data(StateName, NewState, Data);
	_Err ->
	    {stop, normal, NewState}
    end;
handle_info({tcp, _Sock, Data}, StateName, State) ->
    NewState = update_shaper(State, Data),
    process_data(StateName, NewState, Data);
handle_info({tcp_closed, _Sock}, _StateName, State) ->
    ?dbg("connection reset by peer", []),
    {stop, normal, State};
handle_info({tcp_error, _Sock, _Reason}, _StateName, State) ->
    ?dbg("connection error: ~p", [_Reason]),
    {stop, normal, State};
handle_info({timeout, TRef, stop}, _StateName,
	    #state{tref = TRef} = State) ->
    {stop, normal, State};
handle_info({timeout, _TRef, activate}, StateName, State) ->
    activate_socket(State),
    {next_state, StateName, State};
handle_info(Info, StateName, State) ->
    error_logger:error_msg("unexpected info: ~p", [Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, State) ->
    catch (State#state.sock_mod):close(State#state.sock),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
process(State, #stun{class = request,
		     method = ?STUN_METHOD_BINDING,
		     'MESSAGE-INTEGRITY' = undefined} = Msg) ->
    process(State, Msg, undefined);
process(#state{auth = anonymous} = State,
	#stun{class = request, 'MESSAGE-INTEGRITY' = undefined} = Msg) ->
    process(State, Msg, undefined);
process(#state{auth = user} = State,
	#stun{class = request, 'MESSAGE-INTEGRITY' = undefined} = Msg) ->
    Resp = prepare_response(State, Msg),
    {Nonce, Nonces} = make_nonce(State#state.peer,
				 State#state.nonces),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(401),
		  'REALM' = State#state.realm,
		  'NONCE' = Nonce},
    send(State#state{nonces = Nonces}, R);
process(#state{auth = anonymous} = State,
	#stun{class = request,
	      'USERNAME' = User,
	      'REALM' = Realm,
	      'NONCE' = Nonce} = Msg)
  when User /= undefined, Realm /= undefined, Nonce /= undefined ->
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(401)},
    send(State, R);
process(#state{auth = user} = State,
	#stun{class = request,
	      'USERNAME' = User,
	      'REALM' = Realm,
	      'NONCE' = Nonce} = Msg)
  when User /= undefined, Realm /= undefined, Nonce /= undefined ->
    Resp = prepare_response(State, Msg),
    {HaveNonce, Nonces} = have_nonce(Nonce, State#state.nonces),
    case HaveNonce of
	true ->
	    NewState = State#state{nonces = Nonces},
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(401),
			  'REALM' = State#state.realm,
			  'NONCE' = Nonce},
	    case (State#state.auth_fun)(User, Realm) of
		<<"">> ->
		    error_logger:info_msg(
		      "failed long-term STUN authentication "
		      "for ~s@~s from ~s",
		      [User, Realm, addr_to_str(State#state.peer)]),
		    send(NewState, R);
		Pass ->
		    Key = {User, Realm, Pass},
		    case stun_codec:check_integrity(Msg, Key) of
			true ->
			    error_logger:info_msg(
			      "accepted long-term STUN authentication "
			      "for ~s@~s from ~s",
			      [User, Realm, addr_to_str(State#state.peer)]),
			    process(NewState, Msg, Key);
			false ->
			    error_logger:info_msg(
			      "failed long-term STUN authentication "
			      "for ~s@~s from ~s",
			      [User, Realm, addr_to_str(State#state.peer)]),
			    send(NewState, R)
		    end
	    end;
	false ->
	    {NewNonce, NewNonces} = make_nonce(State#state.peer, Nonces),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(438),
			  'REALM' = State#state.realm,
			  'NONCE' = NewNonce},
	    send(State#state{nonces = NewNonces}, R)
    end;
process(State, #stun{class = request,
		     'USERNAME' = User,
		     'REALM' = undefined,
		     'NONCE' = undefined} = Msg) when User /= undefined ->
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(401)},
    send(State, R);
process(State, #stun{class = request} = Msg) ->
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(400)},
    send(State, R);
process(State, #stun{class = indication,
		     method = ?STUN_METHOD_SEND} = Msg) ->
    route_on_turn(State, Msg);
process(State, Msg) when is_record(Msg, turn) ->
    route_on_turn(State, Msg);
process(State, _Msg) ->
    State.

process(State, #stun{class = request, unsupported = [_|_]} = Msg, Secret) ->
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'UNKNOWN-ATTRIBUTES' = Msg#stun.unsupported,
		  'ERROR-CODE' = stun_codec:error(420)},
    send(State, R, Secret);
process(State, #stun{class = request,
		     method = ?STUN_METHOD_BINDING} = Msg, Secret) ->
    Resp = prepare_response(State, Msg),
    AddrPort = State#state.peer,
    R = case stun_codec:version(Msg) of
	    old ->
		Resp#stun{class = response, 'MAPPED-ADDRESS' = AddrPort};
	    new ->
		Resp#stun{class = response, 'XOR-MAPPED-ADDRESS' = AddrPort}
	end,
    send(State, R, Secret);
process(#state{use_turn = false} = State,
	#stun{class = request} = Msg, Secret) ->
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error, 'ERROR-CODE' = stun_codec:error(405)},
    send(State, R, Secret);
process(State, #stun{class = request,
		     method = ?STUN_METHOD_ALLOCATE} = Msg,
	Secret) ->
    Resp = prepare_response(State, Msg),
    AddrPort = State#state.peer,
    SockMod = State#state.sock_mod,
    case turn_sm:find_allocation(AddrPort) of
	{ok, Pid} ->
	    turn:route(Pid, Msg),
	    State;
	_ ->
	    Opts = [{sock, State#state.sock},
		    {sock_mod, SockMod},
		    {username, Msg#stun.'USERNAME'},
		    {realm, State#state.realm},
		    {key, Secret},
		    {server, State#state.server_name},
		    {max_allocs, State#state.max_allocs},
		    {max_permissions, State#state.max_permissions},
		    {addr, AddrPort},
		    {relay_ip, State#state.relay_ip},
		    {min_port, State#state.min_port},
		    {max_port, State#state.max_port} |
		    if SockMod /= gen_udp ->
			    [{owner, self()}];
		       true ->
			    []
		    end],
	    case turn:start(Opts) of
		{ok, Pid} ->
		    cancel_timer(State#state.tref),
		    turn:route(Pid, Msg),
		    State;
		{error, limit} ->
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(486)},
		    send(State, R, Secret);
		{error, stale} ->
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(438)},
		    send(State, R);
		Err ->
		    error_logger:error_msg(
		      "failed to start turn session: ~p", [Err]),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(500)},
		    send(State, R, Secret)
	    end
    end;
process(State, #stun{class = request,
		     method = ?STUN_METHOD_REFRESH} = Msg, Secret) ->
    route_on_turn(State, Msg, Secret);
process(State, #stun{class = request,
		     method = ?STUN_METHOD_CREATE_PERMISSION} = Msg, Secret) ->
    route_on_turn(State, Msg, Secret);
process(State, #stun{class = request,
		    method = ?STUN_METHOD_CHANNEL_BIND} = Msg, Secret) ->
    route_on_turn(State, Msg, Secret);
process(State, #stun{class = request} = Msg, Secret) ->
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error, 'ERROR-CODE' = stun_codec:error(405)},
    send(State, R, Secret);
process(State, _Msg, _Secret) ->
    State.

process_data(NextStateName, #state{buf = Buf} = State, Data) ->
    NewBuf = <<Buf/binary, Data/binary>>,
    case stun_codec:decode(NewBuf, stream) of
	{ok, Msg, Tail} ->
	    ?dbg("got:~n~s", [stun_codec:pp(Msg)]),
	    NewState = process(State, Msg),
	    process_data(NextStateName, NewState#state{buf = <<>>}, Tail);
	empty ->
	    NewState = State#state{buf = <<>>},
	    {next_state, NextStateName, NewState};
	more when size(NewBuf) < ?MAX_BUF_SIZE ->
	    NewState = State#state{buf = NewBuf},
	    {next_state, NextStateName, NewState};
	_ ->
	    {stop, normal, State}
    end.

update_shaper(#state{shaper = Shaper} = State, Data) ->
    {NewShaper, Pause} = stun_shaper:update(Shaper, size(Data)),
    if Pause > 0 ->
    	    erlang:start_timer(Pause, self(), activate);
       true ->
    	    activate_socket(State)
    end,
    State#state{shaper = NewShaper}.

send(State, Data) when is_binary(Data) ->
    SockMod = State#state.sock_mod,
    Sock = State#state.sock,
    case SockMod of
	gen_udp ->
	    {Addr, Port} = State#state.peer,
	    gen_udp:send(Sock, Addr, Port, Data);
	_ ->
	    case SockMod:send(Sock, Data) of
		ok -> ok;
		_  -> exit(normal)
	    end
    end,
    State;
send(State, Msg) ->
    send(State, Msg, undefined).

send(State, Msg, {_JID, Pass}) ->
    send(State, Msg, Pass);
send(State, Msg, Pass) ->
    ?dbg("send:~n~s", [stun_codec:pp(Msg)]),
    case Msg of
	#stun{class = indication} ->
	    send(State, stun_codec:encode(Msg, undefined));
	_ ->
	    send(State, stun_codec:encode(Msg, Pass))
    end.

route_on_turn(State, Msg) ->
    route_on_turn(State, Msg, undefined).

route_on_turn(State, Msg, {_JID, Pass}) ->
    route_on_turn(State, Msg, Pass);
route_on_turn(State, Msg, Pass) ->
    case turn_sm:find_allocation(State#state.peer) of
	{ok, Pid} ->
	    turn:route(Pid, Msg),
	    State;
	_ ->
	    case Msg of
		#stun{class = request} ->
		    Resp = prepare_response(State, Msg),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(437)},
		    send(State, R, Pass);
		_ ->
		    State
	    end
    end.

prepare_state(Opts, Sock, Peer, SockMod) when is_list(Opts) ->
    case proplists:get_bool(use_turn, Opts) of
	true ->
	    lists:foldl(
	      fun({turn_ip, IP}, State) ->
		      case prepare_addr(IP) of
			  {ok, Addr} ->
			      State#state{relay_ip = Addr};
			  {error, _} ->
			      error_logger:error_msg("wrong 'turn_ip' "
						     "value: ~p", [IP]),
			      State
		      end;
		 ({turn_min_port, Min}, State)
		    when is_integer(Min), Min > 1024, Min < 65536 ->
		      State#state{min_port = Min};
		 ({turn_min_port, Wrong}, State) ->
		      error_logger:error_msg("wrong 'turn_min_port' value: "
					     "~p", [Wrong]),
		      State;
		 ({turn_max_port, Max}, State)
		    when is_integer(Max), Max > 1024, Max < 65536 ->
		      State#state{max_port = Max};
		 ({turn_max_port, Wrong}, State) ->
		      error_logger:error_msg("wrong 'turn_max_port' value: "
					     "~p", [Wrong]),
		      State;
		 ({turn_max_allocations, N}, State)
		    when (is_integer(N) andalso N > 0) orelse is_atom(N) ->
		      State#state{max_allocs = N};
		 ({turn_max_allocations, Wrong}, State) ->
		      error_logger:error_msg("wrong 'turn_max_allocations' "
					     "value: ~p", [Wrong]),
		      State;
		 ({turn_max_permissions, N}, State)
		    when (is_integer(N) andalso N > 0) orelse is_atom(N) ->
		      State#state{max_permissions = N};
		 ({turn_max_permissions, Wrong}, State) ->
		      error_logger:error_msg("wrong 'turn_max_permissions' "
					     "value: ~p", [Wrong]),
		      State;
		 ({shaper, S}, State)
		    when S == none orelse (is_integer(S) andalso (S > 0)) ->
		      State#state{shaper = stun_shaper:new(S)};
		 ({shaper, Wrong}, State) ->
		      error_logger:error_msg("wrong 'shaper' "
					     "value: ~p", [Wrong]),
		      State;
		 ({server_name, S}, State) ->
		      try
			  State#state{server_name = iolist_to_binary(S)}
		      catch _:_ ->
			      error_logger:error_msg("wrong 'server_name' "
						     "value: ~p", [S]),
			      State
		      end;
		 ({auth_realm, R}, State) ->
		      try
			  State#state{realm = iolist_to_binary(R)}
		      catch _:_ ->
			      error_logger:error_msg("wrong 'auth_realm' "
						     "value: ~p", [R]),
			      State
		      end;
		 ({auth_fun, F}, State) when is_function(F) ->
		      State#state{auth_fun = F};
		 ({auth_fun, Wrong}, State) ->
		      error_logger:error_msg("wrong 'auth_fun' "
					     "value: ~p", [Wrong]),
		      State;
		 ({auth_type, anonymous}, State) ->
		      State#state{auth = anonymous};
		 ({auth_type, user}, State) ->
		      State#state{auth = user};
		 ({auth_type, Wrong}, State) ->
		      error_logger:error_msg("wrong 'auth_type' "
					     "value: ~p", [Wrong]),
		      State;
		 ({use_turn, _}, State) -> State;
		 (use_turn, State) -> State;
		 (inet, State) -> State;
		 ({ip, _}, State) -> State;
		 ({backlog, _}, State) -> State;
		 ({certfile, _}, State) -> State;
		 ({tls, _}, State) -> State;
		 (tls, State) -> State;
		 (Opt, State) ->
		      error_logger:error_msg(
			"ignoring unknown option ~p", [Opt]),
		      State
	      end,
	      #state{peer = Peer, sock = Sock,
		     sock_mod = SockMod, use_turn = true},
	      Opts);
	_ ->
	    #state{sock = Sock, sock_mod = SockMod, peer = Peer}
    end;
prepare_state(State, _Sock, Peer, _SockMod) ->
    State#state{peer = Peer}.

prepare_addr(IPBin) when is_binary(IPBin) ->
    prepare_addr(binary_to_list(IPBin));
prepare_addr(IPS) when is_list(IPS) ->
    inet_parse:address(IPS);
prepare_addr(T) when is_tuple(T) ->
    try
	inet_parse:address(inet_parse:ntoa(T))
    catch _:_ ->
	    {error, einval}
    end.

activate_socket(#state{sock = Sock, sock_mod = SockMod}) ->
    case SockMod of
	gen_tcp ->
	    inet:setopts(Sock, [{active, once}]);
	_ ->
	    SockMod:setopts(Sock, [{active, once}])
    end.

cancel_timer(undefined) ->
    ok;
cancel_timer(TRef) ->
    case erlang:cancel_timer(TRef) of
	false ->
	    receive
                {timeout, TRef, _} ->
                    ok
            after 0 ->
                    ok
            end;
        _ ->
            ok
    end.

now_priority() ->
    {p1_time_compat:monotonic_time(micro_seconds), p1_time_compat:unique_integer([monotonic])}.

clean_treap(Treap, CleanPriority) ->
    case treap:is_empty(Treap) of
	true ->
	    Treap;
	false ->
	    {_Key, {TS, _}, _Value} = treap:get_root(Treap),
	    if TS > CleanPriority ->
		    clean_treap(treap:delete_root(Treap), CleanPriority);
	       true ->
		    Treap
	    end
    end.

make_nonce(Addr, Nonces) ->
    Priority = now_priority(),
    {TS, _} = Priority,
    Nonce = list_to_binary(integer_to_list(random:uniform(1 bsl 32))),
    NewNonces = clean_treap(Nonces, TS + ?NONCE_LIFETIME),
    {Nonce, treap:insert(Nonce, Priority, Addr, NewNonces)}.

have_nonce(Nonce, Nonces) ->
    TS = p1_time_compat:monotonic_time(micro_seconds),
    NewNonces = clean_treap(Nonces, TS + ?NONCE_LIFETIME),
    case treap:lookup(Nonce, NewNonces) of
	{ok, _, _} ->
	    {true, NewNonces};
	_ ->
	    {false, NewNonces}
    end.

addr_to_str({Addr, Port}) ->
    [inet_parse:ntoa(Addr), $:, integer_to_list(Port)];
addr_to_str(Addr) ->
    inet_parse:ntoa(Addr).

get_sockmod(Opts) ->
    case proplists:get_bool(tls, Opts) of
	true ->
	    fast_tls;
	false ->
	    gen_tcp
    end.

get_certfile(Opts) ->
    case catch iolist_to_binary(proplists:get_value(certfile, Opts)) of
	Filename when is_binary(Filename), Filename /= <<"">> ->
	    Filename;
	_ ->
	    undefined
    end.

maybe_starttls(_Sock, fast_tls, undefined, {IP, Port}) ->
    error_logger:error_msg("failed to start TLS connection for ~s:~p: "
			   "option 'certfile' is not set",
			   [inet_parse:ntoa(IP), Port]),
    {error, eprotonosupport};
maybe_starttls(Sock, fast_tls, CertFile, _PeerAddr) ->
    fast_tls:tcp_to_tls(Sock, [{certfile, CertFile}]);
maybe_starttls(Sock, gen_tcp, _CertFile, _PeerAddr) ->
    {ok, Sock}.

seed() ->
    {A, B, C} = p1_time_compat:timestamp(),
    random:seed(A, B, C).

prepare_response(State, Msg) ->
    #stun{method = Msg#stun.method,
	  magic = Msg#stun.magic,
	  trid = Msg#stun.trid,
	  'SOFTWARE' = State#state.server_name}.
