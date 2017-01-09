%%%-------------------------------------------------------------------
%%% File    : turn_sm.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Description : Registers TURN sessions and credentials
%%% Created : 23 Aug 2009 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
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

-module(turn_sm).

-behaviour(gen_server).

%% API
-export([start_link/0,
	 start/0,
	 find_allocation/1,
	 add_allocation/5,
	 del_allocation/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include("stun.hrl").

-record(state, {}).

%%====================================================================
%% API
%%====================================================================
start() ->
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

find_allocation(AddrPort) ->
    case ets:lookup(turn_allocs, AddrPort) of
	[{_, Pid}] ->
	    {ok, Pid};
	_ ->
	    {error, notfound}
    end.

add_allocation(AddrPort, _User, _Realm, _MaxAllocs, Pid) ->
    ets:insert(turn_allocs, {AddrPort, Pid}),
    ok.

del_allocation(AddrPort, _User, _Realm) ->
    ets:delete(turn_allocs, AddrPort),
    ok.

%%====================================================================
%% gen_server callbacks
%%====================================================================
init([]) ->
    ets:new(turn_allocs, [named_table, public]),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, {error, badarg}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
