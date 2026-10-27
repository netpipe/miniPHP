<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT ?", [[1, 2]]));
