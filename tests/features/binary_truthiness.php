<?php $z = chr(0); var_dump(boolval($z), $z ? "t" : "f", empty($z), boolval(""), boolval("0"), boolval($z . "0"), boolval("0" . $z), "0" . $z == "0", $z == "", $z == 0, $z == null);
