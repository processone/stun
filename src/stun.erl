%%%-------------------------------------------------------------------
%%% File    : stun.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : RFC5389/RFC5766 implementation.
%%% Created :  8 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2023 ProcessOne, SARL. All Rights Reserved.
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

-define(GEN_FSM, p1_fsm).
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

%% helper functions
-export([rand_uniform/0, rand_uniform/1, rand_uniform/2, unmap_v4_addr/1]).

-include("stun.hrl").
-include("stun_logger.hrl").

-define(MAX_BUF_SIZE, 64*1024). %% 64kb
-define(TIMEOUT, 60000). %% 1 minute
-define(TCP_ACTIVE, 500).
-define(NONCE_LIFETIME, 60*1000*1000). %% 1 minute (in usec)
-define(SERVER_NAME, <<"P1 STUN library">>).

-type addr() :: {inet:ip_address(), inet:port_number()}.

-record(state,
	{sock                        :: inet:socket() | fast_tls:tls_socket() | undefined,
	 sock_mod = gen_tcp          :: gen_udp | gen_tcp | fast_tls,
	 peer = {{0,0,0,0}, 0}       :: addr(),
	 tref                        :: reference() | undefined,
	 use_turn = false            :: boolean(),
	 relay_ipv4_ip = {127,0,0,1} :: inet:ip4_address(),
	 relay_ipv6_ip               :: inet:ip6_address() | undefined,
	 min_port = 49152            :: non_neg_integer(),
	 max_port = 65535            :: non_neg_integer(),
	 max_allocs = 10             :: non_neg_integer() | infinity,
	 shaper = none               :: stun_shaper:shaper(),
	 max_permissions = 10        :: non_neg_integer() | infinity,
	 blacklist_clients = []      :: turn:accesslist(),
	 whitelist_clients = []      :: turn:accesslist(),
	 blacklist_peers = []        :: turn:accesslist(),
	 whitelist_peers = []        :: turn:accesslist(),
	 auth = user                 :: anonymous | user,
	 nonces = treap:empty()      :: treap:treap(),
	 realm = <<"">>              :: binary(),
	 auth_fun                    :: function() | undefined,
	 hook_fun                    :: function() | undefined,
	 server_name = ?SERVER_NAME  :: binary() | undefined,
	 buf = <<>>                  :: binary(),
	 session_id                  :: binary() | undefined}).

-define(opt_map,
	[{shaper, fun handle_opt/3},
	 {server_name, fun handle_opt/3},
	 {turn_ipv4_address, #state.relay_ipv4_ip},
	 {turn_ipv6_address, #state.relay_ipv6_ip},
	 {turn_min_port, #state.min_port},
	 {turn_max_port, #state.max_port},
	 {turn_max_allocations, #state.max_allocs},
	 {turn_max_permissions, #state.max_permissions},
	 {turn_blacklist_clients, #state.blacklist_clients},
	 {turn_whitelist_clients, #state.whitelist_clients},
	 {turn_blacklist_peers, #state.blacklist_peers},
	 {turn_whitelist_peers, #state.whitelist_peers},
	 {turn_blacklist, #state.blacklist_peers}, % Deprecated.
	 {turn_whitelist, #state.whitelist_peers}, % Deprecated.
	 {use_turn, #state.use_turn},
	 {auth_type, #state.auth},
	 {auth_realm, #state.realm},
	 {auth_fun, #state.auth_fun},
	 {hook_fun, #state.hook_fun},
	 {inet, none},
	 {ip, none},
	 {backlog, none},
	 {certfile, none},
	 {dhfile, none},
	 {ciphers, none},
	 {protocol_options, none},
	 {tls, none},
	 {proxy_protocol, none},
	 {sock_peer_name, none},
	 {session_id, none}]).

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
    prepare_state(Opts, Sock, {{0,0,0,0}, 0}, gen_udp).

udp_recv(Sock, Addr, Port, Data, State) ->
    NewState = prepare_state(State, Sock, {Addr, Port}, gen_udp),
    case stun_codec:decode(Data, datagram) of
	{ok, Msg} ->
	    ?LOG_DEBUG(#{verbatim => {"Received:~n~s", [stun_codec:pp(Msg)]}}),
	    process(NewState, Msg);
	{error, Reason} ->
	    ?LOG_DEBUG("Cannot parse packet: ~s", [Reason]),
	    NewState
    end.

%%====================================================================
%% gen_fsm callbacks
%%====================================================================
init([Sock, Opts]) ->
    process_flag(trap_exit, true),
    case get_peername(Sock, Opts) of
	{ok, Addr} ->
	    case get_sockmod(Opts, Sock) of
		{ok, SockMod} ->
		    State = prepare_state(Opts, Sock, Addr, SockMod),
		    case maybe_starttls(Sock, SockMod, Opts) of
			{ok, NewSock} ->
			    TRef = erlang:start_timer(?TIMEOUT, self(), stop),
			    NewState = State#state{sock = NewSock, tref = TRef},
			    activate_socket(NewState),
			    {ok, session_established, NewState};
			{error, Reason} ->
			    {stop, Reason}
		    end
	    end;
	{error, Reason} ->
	    {stop, Reason}
    end.

session_established(Event, State) ->
    ?LOG_ERROR("Unexpected event in 'session_established': ~p", [Event]),
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
	{error, Reason} ->
	    ?LOG_INFO("Connection failure: ~s", [Reason]),
	    {stop, normal, NewState}
    end;
handle_info({tcp, _Sock, Data}, StateName, State) ->
    NewState = update_shaper(State, Data),
    process_data(StateName, NewState, Data);
handle_info({tcp_passive, _Sock}, StateName, State) ->
    activate_socket(State),
    {next_state, StateName, State};
handle_info({tcp_closed, _Sock}, _StateName, State) ->
    ?LOG_INFO("Connection reset by peer"),
    {stop, normal, State};
handle_info({tcp_error, _Sock, _Reason}, _StateName, State) ->
    ?LOG_INFO("Connection error: ~p", [_Reason]),
    {stop, normal, State};
handle_info({timeout, TRef, stop}, _StateName,
	    #state{tref = TRef} = State) ->
    ?LOG_INFO("Connection timed out"),
    {stop, normal, State};
handle_info({timeout, _TRef, activate}, StateName, State) ->
    activate_socket(State),
    {next_state, StateName, State};
handle_info(Info, StateName, State) ->
    ?LOG_ERROR("Unexpected info in '~s': ~p", [StateName, Info]),
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
    ?LOG_NOTICE("Rejecting request: Credentials provided for anonymous "
		"service"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(401)},
    run_hook(protocol_error, State, R),
    send(State, R);
process(#state{auth = user} = State,
	#stun{class = request,
	      'USERNAME' = User,
	      'REALM' = Realm,
	      'NONCE' = Nonce} = Msg)
  when User /= undefined, Realm /= undefined, Nonce /= undefined ->
    stun_logger:add_metadata(#{stun_user => User}),
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
		    ?LOG_NOTICE("Failed long-term STUN/TURN authentication"),
		    run_hook(protocol_error, State, R),
		    send(NewState, R);
		Pass0 ->
		    {Pass, IsExpired} = check_expired_tag(Pass0),
		    case check_integrity(User, Realm, Msg, Pass) of
			{true, Key} ->
			    ?LOG_INFO("Accepting long-term STUN/TURN "
				      "authentication"),
			    process(NewState, Msg, Key, IsExpired);
			false ->
			    ?LOG_NOTICE("Failed long-term STUN/TURN "
					"authentication"),
			    run_hook(protocol_error, State, R),
			    send(NewState, R)
		    end
	    end;
	false ->
	    ?LOG_NOTICE("Rejecting request: Nonexistent nonce"),
	    {NewNonce, NewNonces} = make_nonce(State#state.peer, Nonces),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(438),
			  'REALM' = State#state.realm,
			  'NONCE' = NewNonce},
	    run_hook(protocol_error, State, R),
	    send(State#state{nonces = NewNonces}, R)
    end;
process(State, #stun{class = request,
		     'USERNAME' = User,
		     'REALM' = undefined,
		     'NONCE' = undefined} = Msg) when User /= undefined ->
    ?LOG_NOTICE("Rejecting request: Missing realm and nonce"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(401)},
    run_hook(protocol_error, State, R),
    send(State, R);
process(State, #stun{class = request} = Msg) ->
    ?LOG_NOTICE("Rejecting malformed request"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(400)},
    run_hook(protocol_error, State, R),
    send(State, R);
process(State, #stun{class = indication,
		     method = ?STUN_METHOD_SEND} = Msg) ->
    route_on_turn(State, Msg);
process(State, Msg) when is_record(Msg, turn) ->
    route_on_turn(State, Msg);
process(State, _Msg) ->
    State.

process(State, Msg, Secret) ->
    process(State, Msg, Secret, false).

process(State, #stun{class = request, unsupported = [_|_] = Unsupported} = Msg,
	Secret, _IsExpired) ->
    ?LOG_DEBUG("Rejecting request with unknown attribute(s): ~p",
	       [Unsupported]),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'UNKNOWN-ATTRIBUTES' = Unsupported,
		  'ERROR-CODE' = stun_codec:error(420)},
    run_hook(protocol_error, State, R),
    send(State, R, Secret);
process(State, #stun{class = request,
		     method = ?STUN_METHOD_BINDING} = Msg, Secret,
	_IsExpired) ->
    Resp = prepare_response(State, Msg),
    AddrPort = unmap_v4_addr(State#state.peer),
    R = case stun_codec:version(Msg) of
	    old ->
		?LOG_DEBUG("Responding to 'classic' STUN request"),
		Resp#stun{class = response, 'MAPPED-ADDRESS' = AddrPort};
	    new ->
		?LOG_DEBUG("Responding to STUN request"),
		Resp#stun{class = response, 'XOR-MAPPED-ADDRESS' = AddrPort}
	end,
    run_hook(stun_query, State, Msg),
    send(State, R, Secret);
process(#state{use_turn = false} = State,
	#stun{class = request} = Msg, Secret, _IsExpired) ->
    ?LOG_NOTICE("Rejecting TURN request: TURN is disabled"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error, 'ERROR-CODE' = stun_codec:error(405)},
    run_hook(protocol_error, State, R),
    send(State, R, Secret);
process(State, #stun{class = request,
		     method = ?STUN_METHOD_ALLOCATE} = Msg,
	Secret, IsExpired) ->
    Resp = prepare_response(State, Msg),
    AddrPort = State#state.peer,
    case turn_sm:find_allocation(AddrPort) of
	{ok, Pid} ->
	    turn:route(Pid, Msg),
	    State;
	_ when IsExpired ->
	    ?LOG_NOTICE("Rejecting request: credentials expired"),
	    R = Resp#stun{class = error, 'ERROR-CODE' = stun_codec:error(401)},
	    run_hook(protocol_error, State, R),
	    send(State, R);
	_ ->
	    SockMod = State#state.sock_mod,
	    Opts = [{sock, State#state.sock},
		    {sock_mod, SockMod},
		    {username, Msg#stun.'USERNAME'},
		    {realm, State#state.realm},
		    {key, Secret},
		    {server_name, State#state.server_name},
		    {max_allocs, State#state.max_allocs},
		    {max_permissions, State#state.max_permissions},
		    {blacklist_clients, State#state.blacklist_clients},
		    {whitelist_clients, State#state.whitelist_clients},
		    {blacklist_peers, State#state.blacklist_peers},
		    {whitelist_peers, State#state.whitelist_peers},
		    {addr, AddrPort},
		    {relay_ipv4_ip, State#state.relay_ipv4_ip},
		    {relay_ipv6_ip, State#state.relay_ipv6_ip},
		    {min_port, State#state.min_port},
		    {max_port, State#state.max_port},
		    {hook_fun, State#state.hook_fun},
		    {session_id, State#state.session_id} |
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
		    ?LOG_NOTICE("Rejecting request: Allocation quota reached"),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(486)},
		    run_hook(protocol_error, State, R),
		    send(State, R, Secret);
		{error, stale} ->
		    ?LOG_NOTICE("Rejecting request: Stale nonce"),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(438)},
		    run_hook(protocol_error, State, R),
		    send(State, R);
		{error, Reason} ->
		    ?LOG_ERROR("Cannot start TURN session: ~s", [Reason]),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(500)},
		    run_hook(protocol_error, State, R),
		    send(State, R, Secret)
	    end
    end;
process(State, #stun{class = request,
		     method = ?STUN_METHOD_REFRESH} = Msg, Secret,
	_IsExpired) ->
    route_on_turn(State, Msg, Secret);
process(State, #stun{class = request,
		     method = ?STUN_METHOD_CREATE_PERMISSION} = Msg, Secret,
	_IsExpired) ->
    route_on_turn(State, Msg, Secret);
process(State, #stun{class = request,
		    method = ?STUN_METHOD_CHANNEL_BIND} = Msg, Secret,
	_IsExpired) ->
    route_on_turn(State, Msg, Secret);
process(State, #stun{class = request} = Msg, Secret, _IsExpired) ->
    ?LOG_NOTICE("Rejecting request: Method not allowed"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error, 'ERROR-CODE' = stun_codec:error(405)},
    run_hook(protocol_error, State, R),
    send(State, R, Secret).

process_data(NextStateName, #state{buf = Buf} = State, Data) ->
    NewBuf = <<Buf/binary, Data/binary>>,
    case stun_codec:decode(NewBuf, stream) of
	{ok, Msg, Tail} ->
 	    ?LOG_DEBUG(#{verbatim => {"Received:~n~s", [stun_codec:pp(Msg)]}}),
	    NewState = process(State, Msg),
	    process_data(NextStateName, NewState#state{buf = <<>>}, Tail);
	empty ->
	    NewState = State#state{buf = <<>>},
	    {next_state, NextStateName, NewState};
	more when size(NewBuf) < ?MAX_BUF_SIZE ->
	    NewState = State#state{buf = NewBuf},
	    {next_state, NextStateName, NewState};
	{error, Reason} ->
	    ?LOG_DEBUG("Cannot parse packet: ~p", [Reason]),
	    {stop, normal, State}
    end.

update_shaper(#state{shaper = none} = State, _Data) ->
    State;
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

send(State, Msg, Pass) ->
    ?LOG_DEBUG(#{verbatim => {"Sending:~n~s", [stun_codec:pp(Msg)]}}),
    send(State, stun_codec:encode(Msg, Pass)).

route_on_turn(State, Msg) ->
    route_on_turn(State, Msg, undefined).

route_on_turn(State, Msg, Pass) ->
    case turn_sm:find_allocation(State#state.peer) of
	{ok, Pid} ->
	    turn:route(Pid, Msg),
	    State;
	_ ->
	    case Msg of
		#stun{class = request} ->
		    ?LOG_NOTICE("Rejecting request: Allocation mismatch"),
		    Resp = prepare_response(State, Msg),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(437)},
		    run_hook(protocol_error, State, R),
		    send(State, R, Pass);
		_ ->
		    State
	    end
    end.

prepare_state(Opts, Sock, Peer, SockMod) when is_list(Opts) ->
    ID = get_session_id(Opts),
    Auth = get_default_auth(Opts),
    State = #state{session_id = ID,
		   auth = Auth,
		   peer = Peer,
		   sock = Sock,
		   sock_mod = SockMod},
    stun_logger:set_metadata(stun, SockMod, ID, Peer),
    lists:foldl(
      fun({Key, Val}, Acc) ->
	      case proplists:get_value(Key, ?opt_map) of
		  Pos when is_integer(Pos) ->
		      setelement(Pos, Acc, Val);
		  Fun when is_function(Fun) ->
		      Fun(Key, Val, Acc);
		  none ->
		      Acc;
		  undefined ->
		      exit({unknown_option, Key})
	      end
      end, State, proplists:unfold(Opts));
prepare_state(State, _Sock, Peer, SockMod) ->
    ID = stun_logger:make_id(),
    stun_logger:set_metadata(stun, SockMod, ID, Peer),
    State#state{session_id = ID, peer = Peer}.

get_default_auth(Opts) ->
    case proplists:get_bool(use_turn, Opts) of
	true ->
	    user;
	false ->
	    anonymous
    end.

get_session_id(Opts) ->
    case proplists:get_value(session_id, Opts) of
	ID when is_binary(ID) ->
	    ID; % Stick to listener's session ID.
	undefined ->
	    stun_logger:make_id()
    end.

handle_opt(server_name, none, State) ->
    State#state{server_name = undefined};
handle_opt(server_name, Name, State) ->
    State#state{server_name = Name};
handle_opt(shaper, Shaper, State) ->
    State#state{shaper = stun_shaper:new(Shaper)}.

activate_socket(#state{sock = Sock, sock_mod = gen_tcp, shaper = none}) ->
    inet:setopts(Sock, [{active, ?TCP_ACTIVE}]);
activate_socket(#state{sock = Sock, sock_mod = SockMod, shaper = none}) ->
    SockMod:setopts(Sock, [{active, ?TCP_ACTIVE}]);
activate_socket(#state{sock = Sock, sock_mod = gen_tcp}) ->
    inet:setopts(Sock, [{active, once}]);
activate_socket(#state{sock = Sock, sock_mod = SockMod}) ->
    SockMod:setopts(Sock, [{active, once}]).

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
	    if TS < CleanPriority ->
		    clean_treap(treap:delete_root(Treap), CleanPriority);
	       true ->
		    Treap
	    end
    end.

make_nonce(Addr, Nonces) ->
    Priority = now_priority(),
    {TS, _} = Priority,
    Nonce = integer_to_binary(rand_uniform(1 bsl 32)),
    NewNonces = clean_treap(Nonces, TS - ?NONCE_LIFETIME),
    {Nonce, treap:insert(Nonce, Priority, Addr, NewNonces)}.

have_nonce(Nonce, Nonces) ->
    TS = p1_time_compat:monotonic_time(micro_seconds),
    NewNonces = clean_treap(Nonces, TS - ?NONCE_LIFETIME),
    case treap:lookup(Nonce, NewNonces) of
	{ok, _, _} ->
	    {true, NewNonces};
	_ ->
	    {false, NewNonces}
    end.

check_integrity(User, Realm, Msg, Pass) when is_binary(Pass) ->
    check_integrity(User, Realm, Msg, [Pass]);
check_integrity(_User, _Realm, _Msg, []) ->
    false;
check_integrity(User, Realm, Msg, [Pass | T]) ->
    Key = {User, Realm, Pass},
    case stun_codec:check_integrity(Msg, Key) of
	true ->
	    {true, Key};
	false ->
	    check_integrity(User, Realm, Msg, T)
    end.

check_expired_tag({expired, Pass}) ->
    {Pass, true};
check_expired_tag(Pass) ->
    {Pass, false}.

unmap_v4_addr({{0, 0, 0, 0, 0, 16#FFFF, D7, D8}, Port}) ->
    {{D7 bsr 8, D7 band 255, D8 bsr 8, D8 band 255}, Port};
unmap_v4_addr(AddrPort) ->
    AddrPort.

get_sockmod(Opts, Sock) ->
    case proplists:get_value(tls, Opts, false) of
	true ->
	    {ok, fast_tls};
	false ->
	    {ok, gen_tcp};
	optional ->
	    case is_tls_handshake(Sock) of
		true ->
		    {ok, fast_tls};
		false ->
		    {ok, gen_tcp}
	    end
    end.

get_peername(Sock, Opts) ->
    case proplists:get_value(sock_peer_name, Opts) of
	{_, Addr} ->
	    {ok, Addr};
	undefined ->
	    inet:peername(Sock)
    end.

-ifdef(USE_OLD_INET_BACKEND).
-dialyzer({[no_match], [get_sockmod/2]}).
is_tls_handshake(_Sock) ->
    ?LOG_ERROR("Multiplexing TCP and TLS requires a newer Erlang/OTP version"),
    {error, eprotonosupport}.
-else.
is_tls_handshake({_, _, {_, Socket}}) ->
    case socket:recvfrom(Socket, 10, [peek], ?TIMEOUT) of
	{ok, {_, <<22, 3, _:4/binary, 0, _:2/binary, 3>>}} ->
	    ?LOG_DEBUG("Determined transport protocol: TLS"),
	    true;
	{ok, {_, _}} ->
	    ?LOG_DEBUG("Determined transport protocol: TCP"),
	    false;
	{error, Reason} ->
	    ?LOG_INFO("Cannot determine transport protocol: ~s", [Reason]),
	    false
    end.
-endif.

maybe_starttls(Sock, fast_tls, Opts) ->
    case proplists:is_defined(certfile, Opts) of
	true ->
	    TLSOpts = lists:filter(
			fun({certfile, _Val}) ->
				true;
			   ({dhfile, _Val}) ->
				true;
			   ({ciphers, _Val}) ->
				true;
			   ({protocol_options, _Val}) ->
				true;
			   (_Opt) ->
				false
			end, Opts),
	    fast_tls:tcp_to_tls(Sock, [verify_none | TLSOpts]);
	false ->
	    ?LOG_ERROR("Cannot accept TLS connection: "
		       "option 'certfile' is not set"),
	    {error, eprotonosupport}
    end;
maybe_starttls(Sock, gen_tcp, _Opts) ->
    {ok, Sock}.

prepare_response(State, Msg) ->
    #stun{method = Msg#stun.method,
	  magic = Msg#stun.magic,
	  trid = Msg#stun.trid,
	  'SOFTWARE' = State#state.server_name}.

run_hook(HookName,
	 #state{session_id = ID,
		peer = Client,
		sock_mod = SockMod,
		hook_fun = HookFun},
	 #stun{'USERNAME' = User,
	       'REALM' = Realm,
	       'ERROR-CODE' = Reason} = Msg)
  when is_function(HookFun) ->
    Info = #{id => ID,
	     user => User,
	     realm => Realm,
	     client => Client,
	     transport => stun_logger:encode_transport(SockMod),
	     version => stun_codec:version(Msg),
	     reason => Reason},
    ?LOG_DEBUG("Running '~s' hook", [HookName]),
    try HookFun(HookName, Info)
    catch _:Err -> ?LOG_ERROR("Hook '~s' failed: ~p", [HookName, Err])
    end;
run_hook(HookName, _State, _Msg) ->
    ?LOG_DEBUG("No callback function specified for '~s' hook", [HookName]),
    ok.

-define(THRESHOLD, 16#10000000000000000).

-ifdef(RAND_UNIFORM).
rand_uniform() ->
    rand:uniform().

rand_uniform(N) ->
    rand:uniform(N).

rand_uniform(N, M) ->
    rand:uniform(M-N+1) + N-1.
-else.

rand_uniform() ->
    crypto:rand_uniform(0, ?THRESHOLD)/?THRESHOLD.

rand_uniform(N) ->
    crypto:rand_uniform(1, N+1).

rand_uniform(N, M) ->
    crypto:rand_uniform(N, M+1).
-endif.
