<?php
$k = str_repeat("\x01", 32); $n = str_repeat("\x02", 24); $c = sodium_crypto_secretbox("attack at dawn\0!", $n, $k); echo bin2hex($c), " ", bin2hex(sodium_crypto_secretbox_open($c, $n, $k)); var_dump(sodium_crypto_secretbox_open($c . "x", $n, $k), sodium_crypto_secretbox_open("short", $n, $k)); echo bin2hex(sodium_crypto_secretbox("", $n, $k));
