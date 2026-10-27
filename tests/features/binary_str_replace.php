<?php $z = chr(0); $s = "a" . $z . "b" . $z . "c"; echo bin2hex(str_replace($z, "-", $s)), " ", bin2hex(str_replace("b", $z . $z, $s)), " ", bin2hex(str_replace([$z, "a"], ["0", $z], $s));
