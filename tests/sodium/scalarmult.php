<?php
$a = str_repeat("\x05", 32); $b = str_repeat("\x09", 32); echo bin2hex(sodium_crypto_scalarmult($a, sodium_crypto_scalarmult_base($b))), " ", bin2hex(sodium_crypto_scalarmult($b, sodium_crypto_scalarmult_base($a)));
