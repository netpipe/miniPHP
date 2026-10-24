<?php function total($xs) { $t = 0; foreach ($xs as $x) { $t += $x; } return $t; } echo total([1, 2, 3, 4]);
