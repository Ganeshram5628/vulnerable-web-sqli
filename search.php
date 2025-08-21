<?php
$conn = mysqli_connect("localhost", "root", "", "vulndb");

if (isset($_GET['q'])) {
    $search = $_GET['q'];
    $query = "SELECT * FROM users WHERE username LIKE '%$search%'";
    $result = mysqli_query($conn, $query);

    while ($row = mysqli_fetch_assoc($result)) {
        echo "User: " . $row['username'] . "<br>";
    }
}
?>

<form method="GET">
    Search Users: <input name="q"><br>
    <button type="submit">Search</button>
</form>
