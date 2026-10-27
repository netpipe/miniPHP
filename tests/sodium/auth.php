<?php
$k = str_repeat("\x07", 32); $m = sodium_crypto_auth("msg\0", $k); echo bin2hex($m), " "; var_dump(sodium_crypto_auth_verify($m, "msg\0", $k), sodium_crypto_auth_verify($m, "msg", $k));
