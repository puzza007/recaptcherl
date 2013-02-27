-module(recaptcherl).

-export([verify/3]).

-define(VERIFY_URL, "http://www.google.com/recaptcha/api/verify").

-spec verify(inet:ip_address(), binary(), binary()) -> ok | {error, binary()};
            (inet:ip_address(), string(), string()) -> ok | {error, binary()}.
verify(RemoteIp, Challenge, Response) when is_binary(Challenge) andalso is_binary(Response) ->
    verify(RemoteIp, binary_to_list(Challenge), binary_to_list(Response));
verify(RemoteIp, Challenge, Response) ->
    RemoteIpString = inet_parse:ntoa(RemoteIp),
    {ok, PrivateKey } = application:get_env(recaptcherl, private_key),
    Data =
        "privatekey=" ++ PrivateKey ++ "&"
        "remoteip=" ++ RemoteIpString ++ "&"
        "challenge=" ++ Challenge ++ "&"
        "response=" ++ Response,
    Request = {?VERIFY_URL, [], "application/x-www-form-urlencoded", Data},
    Options = [{body_format, binary}],
    case httpc:request(post, Request, [], Options) of
        {ok, {{_, 200, _}, _, Body}} ->
            case binary:split(Body, <<"\n">>) of
                [<<"true">> | _] ->
                    ok;
                [_, Reason | _] ->
                    {error, Reason}
            end;
        {error, _} = Error ->
            Error
    end.
