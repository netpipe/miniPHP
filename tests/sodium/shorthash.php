<?php
echo bin2hex(sodium_crypto_shorthash("", str_repeat("\x0f", 16))), " ", bin2hex(sodium_crypto_shorthash("hello", str_repeat("\x0f", 16)));
