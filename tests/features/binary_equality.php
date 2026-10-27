<?php $z = chr(0); $a = "a" . $z . "b"; $b = "a" . $z . "c"; var_dump($a == $b, $a === $b, $a == "a" . $z . "b", "a" == "a" . $z, $a < $b);
