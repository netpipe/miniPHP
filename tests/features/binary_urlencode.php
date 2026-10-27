<?php $z = chr(0); echo urlencode("a" . $z . "b"), " ", bin2hex(urldecode("a%00b%00")), " ", strlen(urldecode("%00%00%00"));
