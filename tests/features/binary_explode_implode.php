<?php $z = chr(0); $parts = explode($z, "a" . $z . "b" . $z . $z . "c"); echo count($parts), " ", implode("|", $parts), " ", bin2hex(implode($z, ["x", "y"]));
