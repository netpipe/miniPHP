<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT * FROM nope", [])); echo sqlite_error($db);
