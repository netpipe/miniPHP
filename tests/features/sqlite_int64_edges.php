<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT ? AS a, ? AS b, ? + 1 AS c", [9223372036854775807, -9223372036854775807 - 1, 9223372036854775806]));
