%%%----------------------------------------------------------------------
%%% File    : stun_acceptor_sup.erl
%%% Author  : Holger Weiss <holger@zedat.fu-berlin.de>
%%% Purpose : STUN/TURN listener (child) supervisor
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

-module(stun_acceptor_sup).
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
    SupFlags = #{strategy => simple_one_for_one,
		 intensity => 10,
		 period => 1},
    ChildSpecs = [#{id => stun_acceptor,
		    shutdown => brutal_kill,
		    start => {stun_acceptor, start_link, []}}],
    {ok, {SupFlags, ChildSpecs}}.
