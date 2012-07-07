%% @author Daniel Luna <daniel@lunas.se>
%% @copyright 2012 Daniel Luna
%% @doc 
-module(chaos_monkey).
-author('Daniel Luna <daniel@lunas.se>').
-behaviour(gen_server).

-compile(export_all).
%% API
-export([start/0]).
-export([start_link/0]).

-export([find_orphans/0,
         havoc/0,
         havoc/1,
         havoc/2,
         kill/0,
         off/0,
         on/0]).

-export([calm/0]).
-export([kill_ms/1,
         kill_n/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-define(TIMER, 5000).

-record(state, {
          is_active = false,
          avg_wait,
          timer_ref,
          intervals = []}).

start() ->
    application:start(?MODULE).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% START OF EXTERNAL API

find_orphans() ->
    do_find_orphans().

havoc() ->
    havoc(all_but_otp).

havoc(Apps) ->
    havoc(Apps, []).

havoc(Apps, Protected) ->
    do_havoc(Apps, Protected).

kill() ->
    gen_server:call(?SERVER, kill, infinity).

on() ->
    gen_server:call(?SERVER, on, infinity).

off() ->
    gen_server:call(?SERVER, off, infinity).

%% END OF EXTERNAL API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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
    {NewState, ProcInfo} = kill_something(State),
    {reply, {ok, ProcInfo}, NewState};

handle_call(on, _From, State = #state{is_active = false}) ->
    NewState = State#state{avg_wait = ?TIMER, is_active = true},
    self() ! kill_something,
    {reply, {ok, started}, NewState};
handle_call(off, _From, State = #state{is_active = true, timer_ref = Ref}) ->
    timer:cancel(Ref),
    receive kill_something -> ok
    after 0 -> ok
    end,
    NewState = State#state{is_active = false},
    {reply, {ok, stopped}, NewState};
handle_call(on, _From, State = #state{is_active = true}) ->
    {reply, {error, already_running}, State};
handle_call(off, _From, State = #state{is_active = false}) ->
    {reply, {error, not_running}, State};

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

handle_info(kill_something, State = #state{avg_wait = AvgWait}) ->
    {NewState, _Info} = kill_something(State),
    Var = 0.3, %% I.e. 70% to 130% of Waittime
    WaitTime = round(AvgWait * ((1 - Var) + (Var * 2 * random:uniform()))),
    {ok, Ref} = timer:send_after(WaitTime, kill_something),
    {noreply, NewState#state{timer_ref = Ref}};
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

kill_something(State) ->
    kill_something(State, randomize(erlang:processes())).

kill_something(State, []) ->
    p("Nothing is killable!", []),
    {State, []};
kill_something(State = #state{}, [Pid | Pids]) ->
    App = application:get_application(Pid),
    IsSystemProcess = pman_process:is_system_process(Pid),
    IsSystemApp = lists:member(App, [{ok, kernel}, {ok, chaos_monkey}]),
    IsSupervisor = is_supervisor(Pid),
    
    case IsSystemProcess orelse IsSystemApp orelse IsSupervisor of
        true ->
            p_pidinfo(false, Pid, App, IsSystemProcess,
                      IsSystemApp, IsSupervisor),
            kill_something(State, Pids);
        false ->
            p_pidinfo(true, Pid, App, IsSystemProcess,
                      IsSystemApp, IsSupervisor),
            Info = erlang:process_info(Pid),
            p("~p", [Info]),
            DeathReason = kill(Pid),
            p("~p died because of ~p", [Pid, DeathReason]),
            {State, App}
    end.

randomize(Xs) ->
    [V || {_, V} <- lists:sort([{random:uniform(), X} || X <- Xs])].

%% random_process() ->
%%     Ps = erlang:processes(),
%%     lists:nth(random:uniform(length(Ps)), Ps).

p_pidinfo(Killable, Pid, App, IsSystemProcess, IsSystemApp, IsSupervisor) ->
    FKillable = case Killable of
                    true -> "About to";
                    false -> "Cannot"
                end,
    FName = case erlang:process_info(Pid, registered_name) of
                {registered_name, Name} ->
                    io_lib:format(" (~s)", [Name]);
                "" -> ""
            end,
    FApp = case App of
               undefined -> "";
               {ok, A} -> io_lib:format(" in app ~s", [A])
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
    case (App =:= undefined) orelse (Killable =:= true) of
        true ->
            p("~s kill ~p~s~s~s.", [FKillable, Pid, FName, FApp, FImmunities]);
        false ->
            ok
    end.

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
        _ -> false
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

do_find_orphans() ->
    Ps = [{P,
           application:get_application(P),
           pman_process:is_system_process(P)}
          || P <- erlang:processes()],
    lists:zf(fun({P, undefined, false}) ->
                     case is_shell(P) of
                         true -> false;
                         false -> {true, P}
                     end;
                (_) -> false end, Ps).

do_havoc(Apps, Protected) ->
    Ps = processes_by_app(Apps),
    %% Start off by killing everything which doesn't belong to an app
    N0 = case lists:keyfind(undefined, 1, Ps) of
             {undefined, Undefined} ->
                 lists:foldl(
                   fun(Pid, N) ->
                           case is_supervisor(Pid) of
                               true ->
                                   p("Why is there a supervisor which "
                                     "doesn't belong to an application.  "
                                     "Take a closer look at ~p", [Pid]),
                                   N;
                               false ->
                                   kill(Pid),
                                   N + 1
                           end
                   end, 0, Undefined);
             false ->
                 0
           end,
    N = N0,
    {error, not_yet_implemented, N, Ps}.

-define(OTP_APPS,
        [appmon, asn1, common_test, compiler, cosEvent,
         cosEventDomain, cosFileTransfer, cosNotification,
         cosProperty, cosTime, cosTransactions, crypto, debugger,
         dialyzer, diameter, edoc, eldap, erl_docgen, erl_interface,
         erts, et, eunit, gs, hipe, ic, inets, inviso, jinterface,
         kernel, megaco, mnesia, observer, odbc, orber, os_mon,
         otp_mibs, parsetools, percept, pman, public_key, reltool,
         runtime_tools, sasl, snmp, ssh, ssl, stdlib, syntax_tools,
         test_server, toolbar, tools, tv, typer, webtool, wx, xmerl]).

processes_by_app(all) ->
    tag_processes_by_app(fun(_) -> true end);
processes_by_app(all_but_otp) ->
    tag_processes_by_app(fun(App) -> not(lists:member(App, ?OTP_APPS)) end);
%% processes_by_app(all_but_deps) ->
%%     TODO = todo,
%%     tag_processes_by_app(fun(App) -> not(lists:member(App, ?OTP_APPS)) end);
processes_by_app(Apps) ->
    tag_processes_by_app(fun(undefined) -> true;
                            (App) -> lists:member(App, Apps) end).

tag_processes_by_app(IsIncludedF) when is_function(IsIncludedF, 1) ->
    All = [{case application:get_application(P) of
                {ok, App} -> App;
                undefined -> undefined
            end, P} || P <- erlang:processes()],
    OnlyIncludedApps =
        lists:filter(
          fun({App, P}) ->
                  not(pman_process:is_system_process(P))
                      andalso
                      not(lists:member(App, [kernel, chaos_monkey]))
                      andalso
                      IsIncludedF(App)
                      andalso
                      not(is_shell(P))
          end, All),
    lists:foldl(fun({App, P}, [{App, Ps} | Acc]) ->
                        [{App, [P | Ps]} | Acc];
                   ({App, P}, Acc) ->
                        [{App, [P]} | Acc]
                end, [], lists:sort(OnlyIncludedApps)).

%% Theoretically pman_process:is_system_process/1 should say true for
%% the shell.  Well, it doesn't, so this is a workaround until it
%% does.
is_shell(Pid) ->
    %% The shell never belongs to any applicition.  To optimize, check
    %% that application:get_application(Pid) yields undefined before
    %% calling this function.
    {group_leader, Leader} = erlang:process_info(Pid, group_leader),
    case lists:keyfind(shell, 1, group:interfaces(Leader)) of
        {shell, Pid} -> true;
        {shell, Shell} ->
            case erlang:process_info(Shell, dictionary) of
                {dictionary, Dict} ->
                    proplists:get_value(evaluator, Dict) =:= Pid
            end;
        false -> false
    end.

kill(Pid) ->
    erlang:monitor(process, Pid),
    exit(Pid, im_killing_you),
    receive
        {'DOWN', _, process, Pid, Reason} ->
            Reason
    after 500 ->
            exit(Pid, kill),
            receive
                {'DOWN', _, process, Pid, Reason} ->
                    Reason
            end
    end.
