<?php
// PHP 8.1+ htmlspecialchars default is ENT_QUOTES | ENT_SUBSTITUTE: each
// broken UTF-8 sequence becomes U+FFFD (how many is PHP's own rule)
foreach (["ok \u{e9}\u{20ac}\u{1F600}", "\x80", "\xc0\xaf", "\xc3", "\xc3<", "\xe2\x82", "\xe2\x82<", "\xed\xa0\x80",
          "\xe0\x80\xaf", "\xf0\x9f\x98", "\xf0\x9f", "\xf4\x90\x80\x80", "\xf5\x80", "\xff\xfe", "a\0<\xff>\0"] as $s)
    echo bin2hex(htmlspecialchars($s)), "\n";
