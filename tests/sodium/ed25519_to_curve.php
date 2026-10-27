<?php
$kp = sodium_crypto_sign_seed_keypair(str_repeat("S", 32)); echo bin2hex(sodium_crypto_sign_ed25519_sk_to_curve25519(sodium_crypto_sign_secretkey($kp))), " ", bin2hex(sodium_crypto_sign_ed25519_pk_to_curve25519(sodium_crypto_sign_publickey($kp)));
