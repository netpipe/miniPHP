<?php foreach ($_GET as $k => $v) echo bin2hex($k), "=", bin2hex($v), " ", strlen($v), "\n";
