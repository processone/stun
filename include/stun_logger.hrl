%%%----------------------------------------------------------------------
%%% File    : stun_logger.hrl
%%% Author  : Holger Weiss <holger@zedat.fu-berlin.de>
%%% Purpose : Wrap OTP Logger for STUN/TURN logging
%%% Created : 19 Jul 2020 by Holger Weiss <holger@zedat.fu-berlin.de>
%%%
%%%
%%% Copyright (C) 2020 ProcessOne, SARL. All Rights Reserved.
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

-ifdef(USE_OLD_LOGGER).
%%-define(debug, true).
-ifdef(debug).
-define(LOG_DEBUG(Str), stun_logger:log(info, Str)).
-define(LOG_DEBUG(Str, Args), stun_logger:log(info, Str, Args)).
-define(LOG_INFO(Str), stun_logger:log(info, Str)).
-define(LOG_INFO(Str, Args), stun_logger:log(info, Str, Args)).
-else.
-define(LOG_DEBUG(Str), ok).
-define(LOG_DEBUG(Str, Args), begin _ = Args end).
-define(LOG_INFO(Str), ok).
-define(LOG_INFO(Str, Args), begin _ = Args end).
-endif.
-define(LOG_NOTICE(Str), stun_logger:log(info, Str)).
-define(LOG_NOTICE(Str, Args), stun_logger:log(info, Str, Args)).
-define(LOG_WARNING(Str), stun_logger:log(warning, Str)).
-define(LOG_WARNING(Str, Args), stun_logger:log(warning, Str, Args)).
-define(LOG_ERROR(Str), stun_logger:log(error, Str)).
-define(LOG_ERROR(Str, Args), stun_logger:log(error, Str, Args)).
-else. % Use new logging API.
-include_lib("kernel/include/logger.hrl").
-endif.
