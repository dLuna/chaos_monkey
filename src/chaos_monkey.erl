%% @author Daniel Luna <daniel@lunas.se>
%% @copyright 2012 Daniel Luna
%% @doc 
-module(chaos_monkey).
-author('Daniel Luna <daniel@lunas.se>').
-behaviour(gen_server).

%% API
-export([start/0]).
-export([start_link/0]).

-export([kill/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {}).

start() ->
    application:start(?MODULE).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

kill() ->
    gen_server:call(?SERVER, kill, infinity).

init([]) ->
    random:seed(now()),
    {ok, #state{}}.

handle_call(kill, _From, State) ->
    NewState = kill_something(State),
    Reply = ok,
    {reply, Reply, NewState}.

handle_cast(kill, State) ->
    NewState = kill_something(State),
    {noreply, NewState}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

kill_something(State = #state{}) ->
    Victim = random_process(),
    Name =
        case erlang:process_info(Victim, registered_name) of
            [] -> "";
            {registered_name, Reg} -> Reg
        end,
    App = application:get_application(Victim),
    case pman_process:is_system_process(Victim) of
        true ->
            error_logger:info_msg("Cannot kill system process ~p (~s, ~p)",
                                  [Victim, Name, App]),
            kill_something(State);
        false ->
            error_logger:info_msg("About to kill ~p (~s, ~p)",
                                  [Victim, Name, App]),
            exit(Victim, im_killing_you),
            timer:sleep(500),
            exit(Victim, kill),
            State
    end.

random_process() ->
    Ps = erlang:processes(),
    lists:nth(random:uniform(length(Ps)), Ps).
