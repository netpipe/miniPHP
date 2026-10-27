<?php $z = chr(0); echo bin2hex(str_repeat($z . "a", 3)), " ", strlen(str_repeat($z, 1000));
