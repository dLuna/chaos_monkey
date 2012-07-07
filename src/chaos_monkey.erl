%% @author Daniel Luna <daniel@lunas.se>
%% @copyright 2012 Daniel Luna
%% @doc 
-module(chaos_monkey).
-author('Daniel Luna <daniel@lunas.se>').
-behaviour(gen_server).

%% API
-export([start/0]).
-export([start_link/0]).

-export([calm/0]).
-export([kill/0,
         kill_ms/1,
         kill_n/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {intervals = []}).

start() ->
    application:start(?MODULE).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

kill() ->
    gen_server:call(?SERVER, kill, infinity).

kill_ms(Ms) ->
    gen_server:call(?SERVER, {kill_ms, Ms}, infinity).

kill_n(N) ->
    gen_server:call(?SERVER, {kill_n, N}, infinity).

calm() ->
    gen_server:call(?SERVER, calm, infinity).

init([]) ->
    random:seed(now()),
    {ok, #state{}}.

handle_call(kill, _From, State) ->
    NewState = kill_something(State),
    Reply = ok,
    {reply, Reply, NewState};
handle_call({kill_ms, Ms}, _From, State) ->
    case timer:send_interval(Ms, kill) of
        {ok, TRef} ->
            {reply,
             ok,
             State#state{intervals = [TRef | State#state.intervals]}};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_call(calm, _From, State = #state{intervals = Intervals}) ->
    Cancels = [timer:cancel(Interval) || Interval <- Intervals],
    {reply, Cancels, State#state{intervals = []}};
handle_call(_Msg, _From, State) ->
    {reply, {error, unknown_call}, State}.


handle_cast(kill, State) ->
    NewState = kill_something(State),
    {noreply, NewState}.

handle_info(kill, State) ->
    NewState = kill_something(State),
    {noreply, NewState};
handle_info(Info, State) ->
    p("Unknown info ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

kill_something(State = #state{}) ->
    Pid = random_process(),
    App = application:get_application(Pid),
    IsSystemProcess = pman_process:is_system_process(Pid),
    IsSystemApp = lists:member(App, [{ok, kernel}, {ok, chaos_monkey}]),
    IsSupervisor = is_supervisor(Pid),
    case IsSystemProcess orelse IsSystemApp orelse IsSupervisor of
        true ->
            p_pidinfo(false, Pid, App, IsSystemProcess,
                      IsSystemApp, IsSupervisor),
            kill_something(State);
        false ->
            p_pidinfo(true, Pid, App, IsSystemProcess,
                      IsSystemApp, IsSupervisor),
            Info = erlang:process_info(Pid),
            p("~p", [Info]),
            erlang:monitor(process, Pid),
            exit(Pid, im_killing_you),
            DeathReason =
                receive
                    {'DOWN', _, process, Pid, Reason} ->
                        Reason
                after 500 ->
                        exit(Pid, kill),
                        receive
                            {'DOWN', _, process, Pid, Reason} ->
                                Reason
                        end
                end,
            p("~p died because of ~p", [Pid, DeathReason]),
            State
    end.

random_process() ->
    Ps = erlang:processes(),
    lists:nth(random:uniform(length(Ps)), Ps).

p_pidinfo(Killable, Pid, App, IsSystemProcess, IsSystemApp, IsSupervisor) ->
    FKillable = case Killable of
                    true -> "About to";
                    false -> "Cannot"
                end,
    FApp = case App of
               undefined -> "";
               {ok, A} -> io_lib:format(" in app ~s", [A])
           end,
    FName = case erlang:process_info(Pid, registered_name) of
                {registered_name, Name} ->
                    io_lib:format(" with the name of ~s", [Name]);
                "" -> ""
            end,
    Immunities =
        [case IsSystemProcess of
             true -> " is a system process";
             false -> no
         end,
         case IsSystemApp of
             true -> " belongs to a system app";
             false -> no
         end,
         case IsSupervisor of
             true -> " is a supervisor";
             false -> no
         end],
    FImmunities =
        case lists:filter(fun(X) -> X =/= no end, Immunities) of
            [] -> "";
            Imms ->
                [" because it", string:join(Imms, " and")]
        end,
    p("~s kill ~p~s~s~s.", [FKillable, Pid, FApp, FName, FImmunities]).

is_supervisor(Pid) ->
    %% inspired by pman_process:is_system_process2/1 which seems
    %% cleaner somehow to just grabbing the info from the process_info
    %% dictionary (this is what happens in the background anyway).
    {initial_call, Init} = erlang:process_info(Pid, initial_call),
    SortofActualInit =
        case Init of
            {proc_lib, init_p, 5} -> proc_lib:translate_initial_call(Pid);
            Init -> Init
        end,
    case SortofActualInit of
        {supervisor, _, _} -> true;
        _ -> p("Init: ~p", [SortofActualInit]), false
    end.
    
p(Format, Data) ->
    catch throw(get_stacktrace), Stacktrace = erlang:get_stacktrace(),
    MFAInfo = hd(tl(Stacktrace)),
    String =
        case MFAInfo of
            {M, F, A} ->
                format_single_line("~p ~p:~p/~p " ++ Format,
                                   [self(), M, F, A | Data]);
            {M, F, A, Info} ->
                case lists:keysearch(line, 1, Info) of
                    {value, {line, Line}} ->
                        format_single_line("~p ~p:~p/~p #~p " ++ Format,
                                           [self(), M, F, A, Line | Data]);
                    false ->
                        format_single_line("~p ~p:~p/~p " ++ Format,
                                           [self(), M, F, A | Data])
                end
        end,
    io:format("~s~n", [String]).

format_single_line(Format, Data) ->
    oneline(lists:flatten(io_lib:format(Format, Data))).

oneline([$\n | Rest]) -> [$\s | newline(Rest)];
oneline([C | Rest]) -> [C | oneline(Rest)];
oneline([]) -> [].

newline([$\s | Rest]) -> newline(Rest);
newline(Rest) -> oneline(Rest).
