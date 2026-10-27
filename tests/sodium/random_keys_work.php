<?php
$kp = sodium_crypto_box_keypair(); $c = sodium_crypto_box_seal("x", sodium_crypto_box_publickey($kp)); echo sodium_crypto_box_seal_open($c, $kp); $s = sodium_crypto_sign_keypair(); var_dump(sodium_crypto_sign_verify_detached(sodium_crypto_sign_detached("m", sodium_crypto_sign_secretkey($s)), "m", sodium_crypto_sign_publickey($s)));
