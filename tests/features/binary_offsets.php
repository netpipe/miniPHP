<?php $z = chr(0); $s = "a" . $z . "c"; echo bin2hex($s[1]), " ", bin2hex($s[2]), " "; $s[1] = "B"; echo $s, " "; $s[0] = $z; echo bin2hex($s);
