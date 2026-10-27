<?php $z = chr(0); $a = []; $a["k" . $z . "1"] = 1; $a["k" . $z . "2"] = 2; $a["k"] = 3; echo count($a), " "; var_dump(array_key_exists("k" . $z . "1", $a), isset($a["k" . $z . "2"]), $a["k"]);
