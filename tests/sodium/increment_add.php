<?php
$n = "\xff\xff\x00"; sodium_increment($n); echo bin2hex($n), " "; $x = "\xfe\x00"; sodium_add($x, "\x03\x01"); echo bin2hex($x), " "; $c = "\xff"; $copy = $c; sodium_increment($c); echo bin2hex($c), bin2hex($copy);
