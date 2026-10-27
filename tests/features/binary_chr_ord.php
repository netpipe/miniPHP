<?php $z = chr(0); echo ord($z), ord(chr(255)), " ", bin2hex(chr(0) . chr(1) . chr(127) . chr(128) . chr(255));
