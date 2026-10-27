<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT 5 AS \"10\", 6 AS \"07\""));
