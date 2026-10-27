<?php
$k = str_repeat("\x61", 32); $h = str_repeat("\x62", 24); $st = sodium_crypto_secretstream_xchacha20poly1305_init_pull($h, $k); echo strlen($st), " "; var_dump(sodium_crypto_secretstream_xchacha20poly1305_pull($st, str_repeat("z", 40)), sodium_crypto_secretstream_xchacha20poly1305_pull($st, "short"));
