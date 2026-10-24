# miniPHP
a minature version of PHP<br>
<br>
echo, variables, scalars, arrays ([] and array()), arithmetic, concatenation, comparisons, if/elseif/else, while, for, user functions, return, and several builtins.<br>
 
WIP untested<br>

still lacks many things: classes, exceptions, include, multipart/form-data, file uploads, robust locking, full standard library, etc. But it is a reasonably complete little CGI/session-capable PHP-like runtime in one C file.

CGI mode<br>
?a=test query parsing<br>
$_GET<br>
$_POST (application/x-www-form-urlencoded)<br>
$_COOKIE<br>
$_SESSION<br>
$_SERVER<br>
$_REQUEST<br>
session_start()<br>
session_destroy()
header()
setcookie()
output buffering for CGI
file-backed sessions
inline HTML outside <?php ... ?>
<?= $expr ?>
htmlspecialchars()
urlencode() / urldecode()



REQUEST_METHOD=GET QUERY_STRING=a=test ./miniPHP index.php
<br><br>
REQUEST_METHOD=GET ./miniPHP 'index.php?a=test'

