<?php
var_dump(sodium_memcmp("abc", "abc"), sodium_memcmp("abc", "abd"), sodium_compare("\x01\x00", "\x00\x01"), sodium_compare("\x00\x01", "\x01\x00"), sodium_compare("ab", "ab"));
