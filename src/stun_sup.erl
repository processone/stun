%%%----------------------------------------------------------------------
%%% File    : stun_sup.erl
%%% Author  : Evgeniy Khramtsov <ekhramtsov@process-one.net>
%%% Purpose : stun supervisor
%%% Created : 2 May 2013 by Evgeniy Khramtsov <ekhramtsov@process-one.net>
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
%%%----------------------------------------------------------------------

-module(stun_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================
init([]) ->
    StunTmpSup = {stun_tmp_sup, {stun_tmp_sup, start_link, []},
		  permanent, infinity, supervisor, [stun_tmp_sup]},
    TurnTmpSup = {turn_tmp_sup, {turn_tmp_sup, start_link, []},
		  permanent, infinity, supervisor, [turn_tmp_sup]},
    TurnSM = {turn_sm, {turn_sm, start_link, []},
	      permanent, 2000, worker, [turn_sm]},
    StunListen = {stun_listener, {stun_listener, start_link, []},
		  permanent, 2000, worker, [stun_listener]},
    {ok, {{one_for_one, 10, 1}, [TurnSM, StunTmpSup, TurnTmpSup, StunListen]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
