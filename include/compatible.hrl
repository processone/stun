-ifdef(otp_after_18).
-define(RANDOM, rand).
-define(seed(), rand:seed(exs1024)).
-else.
-define(RANDOM, random).
-define(seed(), begin
    {A, B, C} = p1_time_compat:timestamp(),
    random:seed(A, B, C)
end).
-endif.

-ifdef(otp_after_19).
-define(rand_bytes(N), crypto:rand_bytes(N)).
-else.
-define(rand_bytes(N), crypto:strong_rand_bytes(N)).
-endif.
