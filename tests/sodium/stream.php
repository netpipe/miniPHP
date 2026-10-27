<?php
$k = str_repeat("\x51", 32); $n = str_repeat("\x52", 24); echo bin2hex(sodium_crypto_stream(20, $n, $k)), " ", bin2hex(sodium_crypto_stream_xor("abc", $n, $k)), " ", bin2hex(sodium_crypto_stream_xchacha20(20, $n, $k)), " ", bin2hex(sodium_crypto_stream_xchacha20_xor("abc", $n, $k)), " ", bin2hex(sodium_crypto_stream_xchacha20_xor_ic("abc", $n, 5, $k));
