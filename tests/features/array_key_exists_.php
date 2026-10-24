<?php $a = ["a" => null, 0 => 1]; var_dump(array_key_exists("a", $a), isset($a["a"]), array_key_exists("b", $a), array_key_exists(0, $a), array_key_exists("0", $a));
