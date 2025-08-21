<?php
$conn = mysqli_connect("localhost", "root", "", "vulndb");

if (isset($_POST['login'])) {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    $query = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    $result = mysqli_query($conn, $query);

    if (mysqli_num_rows($result)) {
        echo "Login successful! Welcome, " . $user;
    } else {
        echo "Invalid credentials";
    }
}
?>

<form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <button type="submit" name="login">Login</button>
</form>
