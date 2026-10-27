<?php
$b = sodium_crypto_box_seed_keypair(str_repeat("B", 32)); $c = sodium_crypto_box_seal("sealed \0 msg", sodium_crypto_box_publickey($b)); echo strlen($c), " ", bin2hex(sodium_crypto_box_seal_open($c, $b)); var_dump(sodium_crypto_box_seal_open($c, sodium_crypto_box_seed_keypair(str_repeat("C", 32))), sodium_crypto_box_seal_open("x", $b));
