<?php
foreach ([["", 4], ["a", 4], ["abcd", 4], ["abc", 1], ["abcdefgh", 3]] as $sb) { $s = $sb[0]; $b = $sb[1]; $p = sodium_pad($s, $b); echo bin2hex($p), "=", sodium_unpad($p, $b), " "; }
