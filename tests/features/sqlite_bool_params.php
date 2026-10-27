<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT ? AS t, ? AS f", [true, false]));
