<?php $z = chr(0);
var_dump($z . "0" == "0", "0" . $z == "0", "1" . $z == 1, "1" == "1" . $z, is_numeric("5" . $z), is_numeric("5 "));
// PHP 8's numeric-string grammar, not C's strtod: no hex, no inf, no bare space
var_dump(" " == 0, "" == 0, "0x1A" == 26, "inf" == INF, "1e3" == "1000", " 1" == 1, "1 " == 1, ".5" == 0.5, "5." == 5,
         "1e" == 1, "-.e1" == 0, "abc" == 0, "10" == "1e1", "1" == "01", 100 == "1e2", in_array(" ", ["A", "0", 0]));
var_dump(is_numeric("1e"), is_numeric(" \n1.5e+2 \t"), is_numeric("."), is_numeric("-0"), is_numeric("+.5"), is_numeric("0x1A"));
