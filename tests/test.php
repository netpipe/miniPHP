<html>
<body>
<?php
session_start();

if (!isset($_SESSION["count"])) {
    $_SESSION["count"] = 0;
}

$_SESSION["count"] = $_SESSION["count"] + 1;

header("Content-Type: text/html; charset=UTF-8");
?>

<h1>phpmini web demo</h1>

<p>a = <?= htmlspecialchars($_GET["a"]) ?></p>
<p>count = <?= $_SESSION["count"] ?></p>

<?php
if (isset($_COOKIE["theme"])) {
    echo "<p>theme = " . htmlspecialchars($_COOKIE["theme"]) . "</p>";
} else {
    setcookie("theme", "dark", 0, "/");
    echo "<p>Setting theme cookie.</p>";
}
?>

</body>
</html>