<?php $z = chr(0); var_dump(in_array("a" . $z, ["a", "a" . $z]), in_array("a" . $z . "b", ["a"]), array_keys(["x" . $z, "x", "x" . $z], "x" . $z));
