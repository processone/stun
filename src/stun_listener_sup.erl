%%%----------------------------------------------------------------------
%%% Purpose : STUN/TURN listener (parent) supervisor
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

-module(stun_listener_sup).
-behaviour(supervisor).
-author('holger@zedat.fu-berlin.de').
-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%% API.

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% Supervisor callbacks.

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{strategy => one_for_all,
		 intensity => 10,
		 period => 1},
    ChildSpecs = [#{id => stun_acceptor_sup,
		    type => supervisor,
		    start => {stun_acceptor_sup, start_link, []}},
		  #{id => stun_listener,
		    shutdown => 2000,
		    start => {stun_listener, start_link, []}}],
    {ok, {SupFlags, ChildSpecs}}.
