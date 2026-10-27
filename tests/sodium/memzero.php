<?php
$s = "secret"; $t = $s; sodium_memzero($s); var_dump($s, $t);
