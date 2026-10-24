<?php foreach ([1, 2] as $a) { foreach ([1, 2, 3] as $b) { if ($b == 2) break 2; echo $a, $b, " "; } } echo "end";
