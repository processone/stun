%%%-------------------------------------------------------------------
%%% File    : stun.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : RFC5389/RFC5766 implementation.
%%%
%%% Created :  8 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% stun, Copyright (C) 2002-2014   ProcessOne
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

-define(GEN_FSM, gen_fsm).
-behaviour(?GEN_FSM).

%% API
-export([start_link/2,
	 start/2,
	 stop/1,
	 socket_type/0,
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
-export([wait_for_tls/2,
	 session_established/2]).

-include("stun.hrl").

-define(MAX_BUF_SIZE, 64*1024). %% 64kb
-define(TIMEOUT, 60000). %% 1 minute
-define(NONCE_LIFETIME, 60*1000*1000). %% 1 minute (in usec)
-define(DEFAULT_SERVER_NAME, <<"Erlang STUN library">>).

%%-define(debug, true).
-ifdef(debug).
-define(dbg(Str, Args), error_logger:info_msg(Str, Args)).
-else.
-define(dbg(Str, Args), ok).
-endif.

-type addr() :: {inet:ip_address(), inet:port_number()}.
-type port_range() :: {inet:port_number(), inet:port_number()}.

-record(state,
	{sock                        :: inet:socket() | p1_tls:tls_socket(),
	 sock_mod = gen_tcp          :: gen_udp | gen_tcp | p1_tls,
	 certfile                    :: iodata(),
	 peer = {{0,0,0,0}, 0}       :: addr(),
	 tref = make_ref()           :: reference(),
	 use_turn = false            :: boolean(),
	 relay_ip = {127,0,0,1}      :: inet:ip_address(),
	 port_range = {49152, 65535} :: port_range(),
	 max_allocs = unlimited      :: non_neg_integer() | unlimited,
	 shaper = none               :: shaper:shaper(),
	 max_permissions = unlimited :: non_neg_integer() | unlimited,
	 auth = [user]               :: [anonymous | user],
	 nonces = treap:empty()      :: treap:treap(),
	 realm = <<"">>              :: binary(),
	 get_pass_f                  :: function(),
	 server_name = <<"">>        :: binary(),
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

udp_init(Sock, Opts) ->
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
	    inet:setopts(Sock, [{active, once}]),
	    TRef = erlang:start_timer(?TIMEOUT, self(), stop),
	    State = prepare_state(Opts, Sock, Addr, gen_tcp),
	    case proplists:get_value(certfile, Opts) of
		undefined ->
		    {ok, session_established, State#state{tref = TRef}};
		CertFile ->
		    {ok, wait_for_tls,
		     State#state{certfile = CertFile, tref = TRef}}
	    end;
	Err ->
	    Err
    end.

wait_for_tls(Event, State) ->
    error_logger:error_msg("unexpected event in wait_for_tls: ~p", [Event]),
    {next_state, wait_for_tls, State}.

session_established(Event, State) ->
    error_logger:error_msg("unexpected event in session_established: ~p", [Event]),
    {next_state, session_established, State}.

handle_event(stop, _StateName, State) ->
    {stop, normal, State};
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {reply, {error, badarg}, StateName, State}.

handle_info({tcp, Sock, TLSData}, wait_for_tls, State) ->
    NewState = update_shaper(State, TLSData),
    Buf = <<(NewState#state.buf)/binary, TLSData/binary>>,
    %% Check if the initial message is a TLS handshake
    case Buf of
	_ when size(Buf) < 3 ->
	    {next_state, wait_for_tls, NewState#state{buf = Buf}};
	<<_:16, 1, _/binary>> ->
	    TLSOpts = [{certfile, NewState#state.certfile}],
	    {ok, TLSSock} = tls:tcp_to_tls(Sock, TLSOpts),
	    NewState1 = NewState#state{sock = TLSSock,
				      buf = <<>>,
				      sock_mod = tls},
	    case tls:recv_data(TLSSock, Buf) of
		{ok, Data} ->
		    process_data(session_established, NewState1, Data);
		_Err ->
		    {stop, normal, NewState1}
	    end;
	_ ->
	    process_data(session_established, NewState, TLSData)
    end;
handle_info({tcp, _Sock, TLSData}, StateName,
	    #state{sock_mod = tls} = State) ->
    NewState = update_shaper(State, TLSData),
    case tls:recv_data(NewState#state.sock, TLSData) of
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
process(State, #stun{class = request, 'MESSAGE-INTEGRITY' = undefined} = Msg) ->
    case Msg#stun.method of
	?STUN_METHOD_BINDING ->
	    process(State, Msg, undefined);
	_ ->
	    case lists:member(anonymous, State#state.auth) of
		true ->
		    process(State, Msg, undefined);
		false ->
		    Resp = prepare_response(State, Msg),
		    case lists:member(user, State#state.auth) of
			false ->
			    R = Resp#stun{class = error,
					  'ERROR-CODE' = stun_codec:error(401)},
			    send(State, R);
			true ->
			    {Nonce, Nonces} = make_nonce(State#state.peer,
							 State#state.nonces),
			    R = Resp#stun{class = error,
					  'ERROR-CODE' = stun_codec:error(401),
					  'REALM' = State#state.realm,
					  'NONCE' = Nonce},
			    send(State#state{nonces = Nonces}, R)
		    end
	    end
    end;
process(State, #stun{class = request,
		     'USERNAME' = User,
		     'REALM' = Realm,
		     'NONCE' = Nonce} = Msg)
  when User /= undefined, Realm /= undefined, Nonce /= undefined ->
    Resp = prepare_response(State, Msg),
    case lists:member(user, State#state.auth) of
	false ->
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(401)},
	    send(State, R);
	true ->
	    {HaveNonce, Nonces} = have_nonce(Nonce, State#state.nonces),
	    case HaveNonce of
		true ->
		    NewState = State#state{nonces = Nonces},
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(401),
				  'REALM' = State#state.realm,
				  'NONCE' = Nonce},
		    case (State#state.get_pass_f)(User, Realm) of
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
	    end
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
		    {max_allocs, State#state.max_allocs},
		    {max_permissions, State#state.max_permissions},
		    {addr, AddrPort},
		    {relay_ip, State#state.relay_ip},
		    {port_range, State#state.port_range} |
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
    {NewShaper, Pause} = shaper:update(Shaper, size(Data)),
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
    case gen_mod:get_opt(use_turn, Opts, false) of
	true ->
	    IP = get_turn_ip(Opts),
	    PortRange = get_port_range(Opts),
	    MaxAllocs = gen_mod:get_opt(turn_max_allocations, Opts, unlimited),
	    MaxPerms = gen_mod:get_opt(turn_max_permissions, Opts, unlimited),
	    Shaper = gen_mod:get_opt(shaper, Opts, none),
	    Realm = gen_mod:get_opt(realm, Opts, <<"localhost">>),
	    Auth = case gen_mod:get_opt(turn_auth, Opts, [jid]) of
		       L when is_list(L) ->
			   case lists:filter(
				  fun(anonymous) -> true;
				     (user) -> true;
				     (_) -> false
				  end, L) of
			       [] ->
				   error_logger:error_msg(
				     "no valid authentication "
				     "types found, using [user] "
				     "as fallback", []),
				   [user];
			       L1 ->
				   L1
			   end;
		       Bad ->
			   error_logger:error_msg(
			     "wrong turn_auth type ~p, "
			     "using [user] as fallback", [Bad]),
			   [user]
		   end,
	    #state{use_turn = true,
		   relay_ip = IP,
		   port_range = PortRange,
		   max_allocs = MaxAllocs,
		   max_permissions = MaxPerms,
		   sock = Sock,
		   auth = Auth,
		   realm = Realm,
		   shaper = shaper:new(Shaper),
		   sock_mod = SockMod,
		   peer = Peer};
	_ ->
	    #state{sock = Sock, sock_mod = SockMod, peer = Peer}
    end;
prepare_state(State, _Sock, Peer, _SockMod) ->
    State#state{peer = Peer}.

get_turn_ip(Opts) ->
    case proplists:get_value(turn_ip, Opts) of
	IPS when is_list(IPS) ->
	    {ok, Addr} = inet_parse:address(IPS),
	    Addr;
	Addr when is_tuple(Addr) ->
	    Addr;
	undefined ->
	    case inet:getif() of
		{ok, [{Addr, _BCast, _Mask}|_]} ->
		    Addr;
		_ ->
		    error_logger:error_msg("could not detect turn_ip, "
					   "using 127.0.0.1 as fallback", []),
		    {127,0,0,1}
	    end
    end.

get_port_range(Opts) ->
    case lists:keysearch(turn_port_range, 1, Opts) of
	{value, {_, Min, Max}} when 1024 < Min, Min < Max, Max < 65536 ->
	    {Min, Max};
	{value, _} ->
	    error_logger:error_msg("invalid turn_port_range, "
				   "using 49152-65535 as fallback", []),
	    {49152, 65535};
	_ ->
	    {49152, 65535}
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
    {MSec, Sec, USec} = now(),
    -((MSec*1000000 + Sec)*1000000 + USec).

clean_treap(Treap, CleanPriority) ->
    case treap:is_empty(Treap) of
	true ->
	    Treap;
	false ->
	    {_Key, Priority, _Value} = treap:get_root(Treap),
	    if Priority > CleanPriority ->
		    clean_treap(treap:delete_root(Treap), CleanPriority);
	       true ->
		    Treap
	    end
    end.

make_nonce(Addr, Nonces) ->
    Priority = now_priority(),
    Nonce = randoms:get_string(),
    NewNonces = clean_treap(Nonces, Priority + ?NONCE_LIFETIME),
    {Nonce, treap:insert(Nonce, Priority, Addr, NewNonces)}.

have_nonce(Nonce, Nonces) ->
    Priority = now_priority(),
    NewNonces = clean_treap(Nonces, Priority + ?NONCE_LIFETIME),
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

prepare_response(State, Msg) ->
    #stun{method = Msg#stun.method,
	  magic = Msg#stun.magic,
	  trid = Msg#stun.trid,
	  'SOFTWARE' = State#state.server_name}.
