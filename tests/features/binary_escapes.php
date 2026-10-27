<?php
echo bin2hex("\0|\00|\000|\0000|\x0|\x00|\xff|\xFg|\101\60|\u{0}|\u{e9}|\u{1F600}|\u{10FFFF}"), "\n";
echo bin2hex("\e\v\f\$\'\q\x\u\N"), "\n";
echo bin2hex('\0\x41\'\\\n'), "\n";
echo strlen("a\0b"), " ", strlen("\x00\x00"), " ", "a\0b" === "a" . chr(0) . "b" ? "same" : "differ", "\n";
$a = ["k\0" => 1, "k" => 2]; echo count($a), " ", $a["k\0"], "\n";
var_dump("\0" == "", "\x31" == 1, "1\0" == 1);
