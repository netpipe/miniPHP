<?php $a = ["x" => 1]; foreach ($a as $k => $v) { $a[$k] = 99; echo $v; } echo $a["x"];
