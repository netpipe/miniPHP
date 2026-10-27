<?php $z = chr(0); $s = "ab" . $z . "cd" . $z; var_dump(strpos($s, $z), strpos($s, $z, 3), strpos($s, "cd"), strpos($s, "c" . $z), strpos($s, $z . $z));
