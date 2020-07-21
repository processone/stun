%%%-------------------------------------------------------------------
%%% File    : turn.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : Handles TURN allocations, see RFC5766
%%% Created : 23 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2020 ProcessOne, SARL. All Rights Reserved.
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

-module(turn).

-define(GEN_FSM, p1_fsm).
-behaviour(?GEN_FSM).

%% API
-export([start_link/1, start/1, stop/1, route/2]).

%% gen_fsm callbacks
-export([init/1, handle_event/3, handle_sync_event/4,
	 handle_info/3, terminate/3, code_change/4]).

%% gen_fsm states
-export([wait_for_allocate/2, active/2]).

-include("stun.hrl").
-include("stun_logger.hrl").

-define(MAX_LIFETIME, 3600000). %% 1 hour
-define(DEFAULT_LIFETIME, 600000). %% 10 minutes
-define(PERMISSION_LIFETIME, 300000). %% 5 minutes
-define(CHANNEL_LIFETIME, 600000). %% 10 minutes

-type addr() :: {inet:ip_address(), inet:port_number()}.
-type subnet() :: {inet:ip4_address(), 0..32} | {inet:ip6_address(), 0..128}.
-type blacklist() :: [subnet()].

-export_type([blacklist/0]).

-record(state,
	{sock_mod = gen_udp             :: gen_udp | gen_tcp | fast_tls,
	 sock                           :: inet:socket() | fast_tls:tls_socket() | undefined,
	 addr = {{0,0,0,0}, 0}          :: addr(),
	 owner = self()                 :: pid(),
	 username = <<"">>              :: binary(),
	 realm = <<"">>                 :: binary(),
	 key = {<<"">>, <<"">>, <<"">>} :: {binary(), binary(), binary()},
	 server_name = <<"">>           :: binary(),
	 peers = #{}                    :: map(),
	 channels = #{}                 :: map(),
	 permissions = #{}              :: map(),
	 max_permissions                :: non_neg_integer() | atom() | undefined,
	 relay_ipv4_ip = {127,0,0,1}    :: inet:ip4_address(),
	 relay_ipv6_ip                  :: inet:ip6_address() | undefined,
	 min_port = 49152               :: non_neg_integer(),
	 max_port = 65535               :: non_neg_integer(),
	 relay_addr                     :: addr() | undefined,
	 relay_sock                     :: inet:socket() | undefined,
	 last_trid                      :: non_neg_integer() | undefined,
	 last_pkt = <<>>                :: binary(),
	 seq = 1                        :: non_neg_integer(),
	 life_timer                     :: reference() | undefined,
	 blacklist                      :: blacklist() | undefined,
	 rcvd_bytes = 0                 :: non_neg_integer(),
	 rcvd_pkts = 0                  :: non_neg_integer(),
	 sent_bytes = 0                 :: non_neg_integer(),
	 sent_pkts = 0                  :: non_neg_integer()}).

%%====================================================================
%% API
%%====================================================================
start_link(Opts) ->
    ?GEN_FSM:start_link(?MODULE, [Opts], []).

start(Opts) ->
    supervisor:start_child(turn_tmp_sup, [Opts]).

stop(Pid) ->
    ?GEN_FSM:send_all_state_event(Pid, stop).

route(Pid, Msg) ->
    ?GEN_FSM:send_event(Pid, Msg).

%%====================================================================
%% gen_fsm callbacks
%%====================================================================
init([Opts]) ->
    ID = proplists:get_value(session, Opts),
    Owner = proplists:get_value(owner, Opts),
    Username = proplists:get_value(username, Opts),
    Realm = proplists:get_value(realm, Opts),
    AddrPort = proplists:get_value(addr, Opts),
    SockMod = proplists:get_value(sock_mod, Opts),
    State = #state{sock_mod = SockMod,
		   sock = proplists:get_value(sock, Opts),
		   key = proplists:get_value(key, Opts),
		   relay_ipv4_ip = proplists:get_value(relay_ipv4_ip, Opts),
		   relay_ipv6_ip = proplists:get_value(relay_ipv6_ip, Opts),
		   min_port = proplists:get_value(min_port, Opts),
		   max_port = proplists:get_value(max_port, Opts),
		   max_permissions = proplists:get_value(max_permissions, Opts),
		   blacklist = proplists:get_value(blacklist, Opts),
		   server_name = proplists:get_value(server_name, Opts),
		   realm = Realm, addr = AddrPort,
		   username = Username, owner = Owner},
    stun_logger:set_metadata(turn, SockMod, ID, AddrPort, Username),
    MaxAllocs = proplists:get_value(max_allocs, Opts),
    if is_pid(Owner) ->
	    erlang:monitor(process, Owner);
       true ->
	    ok
    end,
    TRef = erlang:start_timer(?DEFAULT_LIFETIME, self(), stop),
    case turn_sm:add_allocation(AddrPort, Username, Realm, MaxAllocs, self()) of
	ok ->
	    {ok, wait_for_allocate, State#state{life_timer = TRef}}
	%%
	%% turn_sm:add_allocation/5 currently doesn't return errors.
	%%
	%% {error, Reason} ->
	%%     {stop, Reason}
    end.

wait_for_allocate(#stun{class = request,
			method = ?STUN_METHOD_ALLOCATE} = Msg,
		  State) ->
    Family = case Msg#stun.'REQUESTED-ADDRESS-FAMILY' of
		 undefined -> inet;
		 ipv4 -> inet;
		 ipv6 -> inet6
	     end,
    IsBlacklisted = blacklisted(State),
    Resp = prepare_response(State, Msg),
    if Msg#stun.'REQUESTED-TRANSPORT' == undefined ->
	    ?LOG_NOTICE("Rejecting allocation request: no transport requested"),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(400)},
	    {stop, normal, send(State, R)};
       Msg#stun.'REQUESTED-TRANSPORT' == unknown ->
	    ?LOG_NOTICE("Rejecting allocation request: unsupported transport"),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(442)},
	    {stop, normal, send(State, R)};
       Msg#stun.'DONT-FRAGMENT' == true ->
	    ?LOG_NOTICE("Rejecting allocation request: dont-fragment not "
			"supported"),
	    R = Resp#stun{class = error,
			  'UNKNOWN-ATTRIBUTES' = [?STUN_ATTR_DONT_FRAGMENT],
			  'ERROR-CODE' = stun_codec:error(420)},
	    {stop, normal, send(State, R)};
       Family == inet6, State#state.relay_ipv6_ip == undefined ->
	    ?LOG_NOTICE("Rejecting allocation request: IPv6 not supported"),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(440)},
	    {stop, normal, send(State, R)};
       IsBlacklisted ->
	    ?LOG_NOTICE("Rejecting allocation request: Client address is "
			"blacklisted"),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(403)},
	    {stop, normal, send(State, R)};
       true ->
	    RelayIP = case Family of
			  inet -> State#state.relay_ipv4_ip;
			  inet6 -> State#state.relay_ipv6_ip
		      end,
	    case allocate_addr(Family, RelayIP,
			       {State#state.min_port, State#state.max_port}) of
		{ok, RelayPort, RelaySock} ->
		    Lifetime = time_left(State#state.life_timer),
		    AddrPort = stun:unmap_v4_addr(State#state.addr),
		    RelayAddr = {RelayIP, RelayPort},
		    stun_logger:add_metadata(
		      #{stun_relay => stun_logger:encode_addr(RelayAddr)}),
		    ?LOG_INFO("Creating TURN allocation (lifetime: ~B seconds)",
			      [Lifetime]),
		    R = Resp#stun{class = response,
				  'XOR-RELAYED-ADDRESS' = RelayAddr,
				  'LIFETIME' = Lifetime,
				  'XOR-MAPPED-ADDRESS' = AddrPort},
		    NewState = send(State, R),
		    {next_state, active,
		     NewState#state{relay_sock = RelaySock,
				    relay_addr = RelayAddr}};
		Err ->
		    ?LOG_ERROR("Cannot allocate TURN relay: ~s",
			       [format_error(Err)]),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = stun_codec:error(508)},
		    {stop, normal, send(State, R)}
	    end
    end;
wait_for_allocate(Event, State) ->
    ?LOG_ERROR("Unexpected event in 'wait_for_allocate': ~p", [Event]),
    {next_state, wait_for_allocate, State}.

active(#stun{trid = TrID}, #state{last_trid = TrID} = State) ->
    send(State, State#state.last_pkt),
    {next_state, active, State};
active(#stun{class = request,
	     method = ?STUN_METHOD_ALLOCATE} = Msg, State) ->
    ?LOG_NOTICE("Rejecting allocation request: Relay already allocated"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(437)},
    {next_state, active, send(State, R)};
active(#stun{class = request,
	     'REQUESTED-ADDRESS-FAMILY' = ipv4,
	     method = ?STUN_METHOD_REFRESH} = Msg,
       #state{relay_addr = {{_, _, _, _, _, _, _, _}, _}} = State) ->
    ?LOG_NOTICE("Rejecting refresh request: IPv4 requested for IPv6 peer"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(443)},
    {next_state, active, send(State, R)};
active(#stun{class = request,
	     'REQUESTED-ADDRESS-FAMILY' = ipv6,
	     method = ?STUN_METHOD_REFRESH} = Msg,
       #state{relay_addr = {{_, _, _, _}, _}} = State) ->
    ?LOG_NOTICE("Rejecting refresh request: IPv6 requested for IPv4 peer"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(443)},
    {next_state, active, send(State, R)};
active(#stun{class = request,
	     method = ?STUN_METHOD_REFRESH} = Msg, State) ->
    Resp = prepare_response(State, Msg),
    case Msg#stun.'LIFETIME' of
	0 ->
	    ?LOG_INFO("Client requested closing the TURN session"),
	    R = Resp#stun{class = response, 'LIFETIME' = 0},
	    {stop, normal, send(State, R)};
	LifeTime ->
	    cancel_timer(State#state.life_timer),
	    MSecs = if LifeTime == undefined ->
			    ?DEFAULT_LIFETIME;
		       true ->
			    lists:min([LifeTime*1000, ?MAX_LIFETIME])
		    end,
	    ?LOG_INFO("Refreshing TURN allocation (lifetime: ~B seconds)",
		      [MSecs div 1000]),
	    TRef = erlang:start_timer(MSecs, self(), stop),
	    R = Resp#stun{class = response,
			  'LIFETIME' = (MSecs div 1000)},
	    {next_state, active, send(State#state{life_timer = TRef}, R)}
    end;
active(#stun{class = request,
	     'XOR-PEER-ADDRESS' = XorPeerAddrs,
	     method = ?STUN_METHOD_CREATE_PERMISSION} = Msg, State) ->
    {Addrs, _Ports} = lists:unzip(XorPeerAddrs),
    Resp = prepare_response(State, Msg),
    case update_permissions(State, Addrs) of
	{ok, NewState} ->
	    R = Resp#stun{class = response},
	    {next_state, active, send(NewState, R)};
	{error, Code} ->
	    Err = {_, Txt} = stun_codec:error(Code),
	    ?LOG_NOTICE("Rejecting permission creation request: ~s", [Txt]),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = Err},
	    {next_state, active, send(State, R)}
    end;
active(#stun{class = indication,
	     method = ?STUN_METHOD_SEND,
	     'XOR-PEER-ADDRESS' = [{Addr, Port}],
	     'DATA' = Data}, State) when is_binary(Data) ->
    State1 = case maps:find(Addr, State#state.permissions) of
		 {ok, _} ->
		     gen_udp:send(State#state.relay_sock, Addr, Port, Data),
		     count_sent(State, Data);
		 error ->
		     State
	     end,
    {next_state, active, State1};
active(#stun{class = request,
	     'CHANNEL-NUMBER' = Channel,
	     'XOR-PEER-ADDRESS' = [{Addr, _Port} = Peer],
	     method = ?STUN_METHOD_CHANNEL_BIND} = Msg, State)
  when is_integer(Channel), Channel >= 16#4000, Channel =< 16#7ffe ->
    Resp = prepare_response(State, Msg),
    case {maps:find(Channel, State#state.channels),
	  maps:find(Peer, State#state.peers)} of
	{_, {ok, OldChannel}} when Channel /= OldChannel ->
	    ?LOG_NOTICE("Rejecting channel binding request: Peer already bound "
			"to a different channel (~.16B)", [OldChannel]),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(400)},
	    {next_state, active, send(State, R)};
	{{ok, {OldPeer, _}}, _} when Peer /= OldPeer ->
	    ?LOG_NOTICE("Rejecting channel binding request: Channel already "
			"bound to a different peer (~s)",
			[stun_logger:encode_addr(OldPeer)]),
	    R = Resp#stun{class = error,
			  'ERROR-CODE' = stun_codec:error(400)},
	    {next_state, active, send(State, R)};
	{FindResult, _} ->
	    case update_permissions(State, [Addr]) of
		{ok, NewState0} ->
		    _Op = case FindResult of
			      {ok, {_, OldTRef}} ->
				  cancel_timer(OldTRef),
				  maybe_log(<<"Refreshing">>);
			      _ ->
				  maybe_log(<<"Binding">>)
			  end,
		    TRef = erlang:start_timer(?CHANNEL_LIFETIME, self(),
					      {channel_timeout, Channel}),
		    Peers = maps:put(Peer, Channel, State#state.peers),
		    Chans = maps:put(Channel, {Peer, TRef},
				     State#state.channels),
		    NewState = NewState0#state{peers = Peers, channels = Chans},
		    ?LOG_INFO("~s TURN channel ~.16B for peer ~s",
			      [_Op, Channel, stun_logger:encode_addr(Peer)]),
		    R = Resp#stun{class = response},
		    {next_state, active, send(NewState, R)};
		{error, Code} ->
		    Err = {_, Txt} = stun_codec:error(Code),
		    ?LOG_NOTICE("Rejecting channel binding request: ~s", [Txt]),
		    R = Resp#stun{class = error,
				  'ERROR-CODE' = Err},
		    {next_state, active, send(State, R)}
	    end
    end;
active(#stun{class = request,
	     method = ?STUN_METHOD_CHANNEL_BIND} = Msg, State) ->
    ?LOG_NOTICE("Rejecting channel binding request: Missing channel number "
		"and/or peer address"),
    Resp = prepare_response(State, Msg),
    R = Resp#stun{class = error,
		  'ERROR-CODE' = stun_codec:error(400)},
    {next_state, active, send(State, R)};
active(#turn{channel = Channel, data = Data}, State) ->
    case maps:find(Channel, State#state.channels) of
	{ok, {{Addr, Port}, _}} ->
	    gen_udp:send(State#state.relay_sock,
			 Addr, Port, Data),
	    State1 = count_sent(State, Data),
	    {next_state, active, State1};
	error ->
	    {next_state, active, State}
    end;
active(Event, State) ->
    ?LOG_ERROR("Unexpected event in 'active': ~p", [Event]),
    {next_state, active, State}.

handle_event(stop, _StateName, State) ->
    {stop, normal, State};
handle_event(Event, StateName, State) ->
    ?LOG_ERROR("Unexpected event in '~s': ~p", [StateName, Event]),
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {reply, {error, badarg}, StateName, State}.

handle_info({udp, Sock, Addr, Port, Data}, StateName, State) ->
    inet:setopts(Sock, [{active, once}]),
    Peer = {Addr, Port},
    case {maps:find(Addr, State#state.permissions),
	  maps:find(Peer, State#state.peers)} of
	{{ok, _}, {ok, Channel}} ->
	    TurnMsg = #turn{channel = Channel, data = Data},
	    State1 = count_rcvd(State, Data),
	    {next_state, StateName, send(State1, TurnMsg)};
	{{ok, _}, error} ->
	    Seq = State#state.seq,
	    Ind = #stun{class = indication,
			method = ?STUN_METHOD_DATA,
			trid = Seq,
			'XOR-PEER-ADDRESS' = [Peer],
			'DATA' = Data},
	    State1 = count_rcvd(State, Data),
	    {next_state, StateName, send(State1#state{seq = Seq+1}, Ind)};
	{error, _} ->
	    {next_state, StateName, State}
    end;
handle_info({timeout, _Tref, stop}, _StateName, State) ->
    {stop, normal, State};
handle_info({timeout, _Tref, {permission_timeout, Addr}},
	    StateName, State) ->
    ?LOG_INFO("TURN permission for ~s timed out",
	      [stun_logger:encode_addr(Addr)]),
    case maps:find(Addr, State#state.permissions) of
	{ok, _} ->
	    Perms = maps:remove(Addr, State#state.permissions),
	    {next_state, StateName, State#state{permissions = Perms}};
	error ->
	    {next_state, StateName, State}
    end;
handle_info({timeout, _Tref, {channel_timeout, Channel}},
	    StateName, State) ->
    case maps:find(Channel, State#state.channels) of
	{ok, {Peer, _}} ->
	    ?LOG_INFO("TURN channel ~.16B for peer ~s timed out",
		      [Channel, stun_logger:encode_addr(Peer)]),
	    Chans = maps:remove(Channel, State#state.channels),
	    Peers = maps:remove(Peer, State#state.peers),
	    {next_state, StateName, State#state{channels = Chans,
						peers = Peers}};
	error ->
	    {next_state, StateName, State}
    end;
handle_info({'DOWN', _Ref, _, _, _}, _StateName, State) ->
    {stop, normal, State};
handle_info(Info, StateName, State) ->
    ?LOG_ERROR("Unexpected info in '~s': ~p", [StateName, Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, State) ->
    AddrPort = State#state.addr,
    Username = State#state.username,
    Realm = State#state.realm,
    RcvdBytes = State#state.rcvd_bytes,
    RcvdPkts = State#state.rcvd_pkts,
    SentBytes = State#state.sent_bytes,
    SentPkts = State#state.sent_pkts,
    case State#state.relay_addr of
	undefined ->
	    ok;
	_RAddrPort ->
	    ?LOG_INFO("Deleting TURN allocation")
    end,
    if is_pid(State#state.owner) ->
	    stun:stop(State#state.owner);
       true ->
	    ok
    end,
    ?LOG_INFO("Relayed ~B KiB (in: ~B B / ~B packets, out: ~B B / ~B packets)",
	      [round((RcvdBytes + SentBytes) / 1024), RcvdBytes, RcvdPkts,
	       SentBytes, SentPkts]),
    turn_sm:del_allocation(AddrPort, Username, Realm).

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
update_permissions(_State, []) ->
    {error, 400};
update_permissions(#state{permissions = Perms, max_permissions = Max}, Addrs)
  when map_size(Perms) + length(Addrs) > Max ->
    {error, 508};
update_permissions(#state{relay_addr = {IP, _}} = State, Addrs) ->
    case {families_match(IP, Addrs), blacklisted(State, Addrs)} of
	{true, false} ->
	    Perms = lists:foldl(
		      fun(Addr, Acc) ->
			      _Op = case maps:find(Addr, Acc) of
					{ok, OldTRef} ->
					    cancel_timer(OldTRef),
					    maybe_log(<<"Refreshing">>);
					error ->
					    maybe_log(<<"Creating">>)
				    end,
			      TRef = erlang:start_timer(
				       ?PERMISSION_LIFETIME, self(),
				       {permission_timeout, Addr}),
			      ?LOG_INFO("~s TURN permission for ~s",
					[_Op, stun_logger:encode_addr(Addr)]),
			      maps:put(Addr, TRef, Acc)
		      end, State#state.permissions, Addrs),
	    {ok, State#state{permissions = Perms}};
	{false, _} ->
	    {error, 443};
	{_, true} ->
	    {error, 403}
    end.

send(State, Pkt) when is_binary(Pkt) ->
    SockMod = State#state.sock_mod,
    Sock = State#state.sock,
    if SockMod == gen_udp ->
	    {Addr, Port} = State#state.addr,
	    gen_udp:send(Sock, Addr, Port, Pkt);
       true ->
	    case SockMod:send(Sock, Pkt) of
		ok ->
		    ok;
		_  ->
		    ?LOG_INFO("Cannot respond to client: Connection closed"),
		    exit(normal)
	    end
    end;
send(State, Msg) ->
    ?LOG_DEBUG(#{verbatim => {"Sending:~n~s", [stun_codec:pp(Msg)]}}),
    Key = State#state.key,
    case Msg of
	#stun{class = indication} ->
	    send(State, stun_codec:encode(Msg)),
	    State;
	#stun{class = response} ->
	    Pkt = stun_codec:encode(Msg, Key),
	    send(State, Pkt),
	    State#state{last_trid = Msg#stun.trid,
			last_pkt = Pkt};
	_ ->
	    send(State, stun_codec:encode(Msg, Key)),
	    State
    end.

time_left(TRef) ->
    erlang:read_timer(TRef) div 1000.

%% Simple port randomization algorithm from
%% draft-ietf-tsvwg-port-randomization-04
allocate_addr(Family, Addr, {Min, Max}) ->
    Count = Max - Min + 1,
    Next = Min + stun:rand_uniform(Count) - 1,
    allocate_addr(Family, Addr, Min, Max, Next, Count).

allocate_addr(_Family, _Addr, _Min, _Max, _Next, 0) ->
    {error, eaddrinuse};
allocate_addr(Family, Addr, Min, Max, Next, Count) ->
    case gen_udp:open(Next, [binary, Family, {ip, Addr}, {active, once}]) of
	{ok, Sock} ->
	    case inet:sockname(Sock) of
		{ok, {_, Port}} ->
		    {ok, Port, Sock};
		Err ->
		    Err
	    end;
	{error, eaddrinuse} ->
	    if Next == Max ->
		    allocate_addr(Family, Addr, Min, Max, Min, Count-1);
	       true ->
		    allocate_addr(Family, Addr, Min, Max, Next+1, Count-1)
	    end;
	{error, eaddrnotavail} when is_tuple(Addr) ->
	    allocate_addr(Family, any, Min, Max, Next, Count);
	Err ->
	    Err
    end.

families_match(RelayAddr, Addrs) ->
    lists:all(fun(Addr) -> family_matches(RelayAddr, Addr) end, Addrs).

family_matches({_, _, _, _}, {_, _, _, _}) ->
    true;
family_matches({_, _, _, _, _, _, _, _}, {_, _, _, _, _, _, _, _}) ->
    true;
family_matches(_Addr1, _Addr2) ->
    false.

blacklisted(#state{addr = {IP, _Port}} = State) ->
    blacklisted(State, [IP]).

blacklisted(#state{blacklist = Blacklist}, IPs) ->
    lists:any(
      fun(IP) ->
	      lists:any(
		fun({Net, Mask}) ->
			match_subnet(IP, Net, Mask)
		end, Blacklist)
      end, IPs).

match_subnet({_, _, _, _} = IP,
	     {_, _, _, _} = Net, Mask) ->
    IPInt = ip_to_integer(IP),
    NetInt = ip_to_integer(Net),
    M = bnot (1 bsl (32 - Mask) - 1),
    IPInt band M =:= NetInt band M;
match_subnet({_, _, _, _, _, _, _, _} = IP,
	     {_, _, _, _, _, _, _, _} = Net, Mask) ->
    IPInt = ip_to_integer(IP),
    NetInt = ip_to_integer(Net),
    M = bnot (1 bsl (128 - Mask) - 1),
    IPInt band M =:= NetInt band M;
match_subnet({_, _, _, _} = IP,
	     {0, 0, 0, 0, 0, 16#FFFF, _, _} = Net, Mask) ->
    IPInt = ip_to_integer({0, 0, 0, 0, 0, 16#FFFF, 0, 0}) + ip_to_integer(IP),
    NetInt = ip_to_integer(Net),
    M = bnot (1 bsl (128 - Mask) - 1),
    IPInt band M =:= NetInt band M;
match_subnet({0, 0, 0, 0, 0, 16#FFFF, _, _} = IP,
	     {_, _, _, _} = Net, Mask) ->
    IPInt = ip_to_integer(IP) - ip_to_integer({0, 0, 0, 0, 0, 16#FFFF, 0, 0}),
    NetInt = ip_to_integer(Net),
    M = bnot (1 bsl (32 - Mask) - 1),
    IPInt band M =:= NetInt band M;
match_subnet(_, _, _) ->
    false.

ip_to_integer({IP1, IP2, IP3, IP4}) ->
    IP1 bsl 8 bor IP2 bsl 8 bor IP3 bsl 8 bor IP4;
ip_to_integer({IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}) ->
    IP1 bsl 16 bor IP2 bsl 16 bor IP3 bsl 16 bor IP4 bsl 16
	bor IP5 bsl 16 bor IP6 bsl 16 bor IP7 bsl 16 bor IP8.

format_error({error, Reason}) ->
    case inet:format_error(Reason) of
	"unknown POSIX error" ->
	    Reason;
	Res ->
	    Res
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

prepare_response(State, Msg) ->
    #stun{method = Msg#stun.method,
	  magic = Msg#stun.magic,
	  trid = Msg#stun.trid,
	  'SOFTWARE' = State#state.server_name}.

count_sent(#state{sent_bytes = SentSize,
		  sent_pkts = SentPkts} = State, Data) ->
    State#state{sent_bytes = SentSize + byte_size(Data),
		sent_pkts = SentPkts + 1}.

count_rcvd(#state{rcvd_bytes = RcvdSize,
		  rcvd_pkts = RcvdPkts} = State, Data) ->
    State#state{rcvd_bytes = RcvdSize + byte_size(Data),
		rcvd_pkts = RcvdPkts + 1}.

-ifdef(USE_OLD_LOGGER).
-ifdef(debug).
maybe_log(Term) -> Term.
-else.
maybe_log(_Term) -> ok.
-endif.
-else.
maybe_log(Term) -> Term.
-endif.
