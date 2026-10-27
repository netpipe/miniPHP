<?php $z = chr(0); $s = ""; for ($i = 0; $i < 256; $i++) { $s .= chr($i); } echo strlen($s), " ", " ", bin2hex(substr($s, 250));
