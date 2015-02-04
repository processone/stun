%%%----------------------------------------------------------------------
%%% File    : stun_shaper.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Functions to control connections traffic
%%% Created :  9 Feb 2003 by Alexey Shchepin <alexey@process-one.net>
%%%
%%%
%%% stun, Copyright (C) 2002-2015   ProcessOne
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
