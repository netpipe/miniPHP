<?php $z = chr(0); $b = hex2bin("00ff00aa0000"); echo strlen($b), " ", bin2hex($b), " ", bin2hex(hex2bin(bin2hex($b . $z)));
