<?php $z = chr(0); echo bin2hex(trim($z . " x " . $z)), " ", bin2hex(trim("xx" . $z . "yy" . $z, "x")), " ", bin2hex(rtrim("a" . $z . $z));
