<?php $z = chr(0); $s = "ab" . $z . "cd" . $z . "ef"; echo bin2hex(substr($s, 1, 4)), " ", bin2hex(substr($s, -3)), " ", strlen(substr($s, 2));
