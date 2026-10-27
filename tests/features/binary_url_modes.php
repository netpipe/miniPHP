<?php
$s = "a b~*-_.+/%&=\0\xff";
echo urlencode($s), "\n", rawurlencode($s), "\n";
echo bin2hex(urldecode("a+b%20%00%2B")), " ", bin2hex(rawurldecode("a+b%20%00%2B")), "\n";
echo urldecode(urlencode($s)) === $s ? "round trip" : "broken", " ", rawurldecode(rawurlencode($s)) === $s ? "round trip" : "broken", "\n";
