%%%----------------------------------------------------------------------
%%% File    : stun_shaper.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Functions to control connections traffic
%%% Created :  9 Feb 2003 by Alexey Shchepin <alexey@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2015 ProcessOne, SARL. All Rights Reserved.
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

-module(stun_shaper).

-author('alexey@process-one.net').

-export([new/1, update/2]).

-record(maxrate, {maxrate  = 0   :: integer(),
                  lastrate = 0.0 :: float(),
                  lasttime = 0   :: integer()}).

-type shaper() :: none | #maxrate{}.

-export_type([shaper/0]).

%%%===================================================================
%%% API
%%%===================================================================
-spec new(none | integer()) -> shaper().

new(none) -> none;
new(MaxRate) when is_integer(MaxRate) ->
    #maxrate{maxrate = MaxRate, lastrate = 0.0,
	     lasttime = now_to_usec(now())}.

-spec update(shaper(), integer()) -> {shaper(), integer()}.

update(none, _Size) -> {none, 0};
update(#maxrate{} = State, Size) ->
    MinInterv = 1000 * Size /
		  (2 * State#maxrate.maxrate - State#maxrate.lastrate),
    Interv = (now_to_usec(now()) - State#maxrate.lasttime) /
	       1000,
    Pause = if MinInterv > Interv ->
		   1 + trunc(MinInterv - Interv);
	       true -> 0
	    end,
    NextNow = now_to_usec(now()) + Pause * 1000,
    {State#maxrate{lastrate =
		       (State#maxrate.lastrate +
			  1000000 * Size / (NextNow - State#maxrate.lasttime))
			 / 2,
		   lasttime = NextNow},
     Pause}.

now_to_usec({MSec, Sec, USec}) ->
    (MSec * 1000000 + Sec) * 1000000 + USec.
