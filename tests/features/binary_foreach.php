<?php $z = chr(0); foreach (["a" . $z => $z . "b"] as $k => $v) { echo strlen($k), strlen($v), bin2hex($k . $v); }
