<?php function first($xs) { foreach ($xs as $x) { return $x; } return null; } echo first(["a", "b"]);
