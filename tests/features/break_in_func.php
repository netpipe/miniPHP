<?php function f() { for ($i = 0; $i < 9; $i++) { if ($i == 2) break; } return $i; } for ($k = 0; $k < 3; $k++) { echo f(); }
