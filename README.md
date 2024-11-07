<?php
require 'DBConnection.php';


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    if (isset($_POST['signUp'])) {
        $firstName = $_POST['fName'];
        $lastName = $_POST['lName'];
        $email = $_POST['email'];
        $password = $_POST['password'];

        $stmt = $conn->prepare("INSERT INTO users (firstName, lastName, email, password) VALUES (?, ?, ?, ?)");
        if ($stmt === false) {
            die('Prepare failed: ' . htmlspecialchars($conn->error));
        }
        $stmt->bind_param("ssss", $firstName, $lastName, $email, $password);

        
        if ($stmt->execute()) {
            header('Location: index.html');
            exit();
        } else {
            header('Location: ../index.html?error=' . urlencode("Error: " . $stmt->error));
            exit();
        }
    }

    
    if (isset($_POST['signIn'])) {
        $email = $_POST['email'];
        $password = $_POST['password'];

        // Prepare the SQL statement to fetch user data
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? AND password = ?");
        $stmt->bind_param("ss", $email, $password);
        $stmt->execute();
        $result = $stmt->get_result();

        
        if ($result->num_rows === 1) {
            header('Location: http://localhost/sql_project/profile.php');
            exit();
        } 
        else{
            header('Location: ../index.html?error=' . urlencode("Invalid email or password."));
            exit();
        }
        
        $stmt->close();
    }

}
$conn->close();

?>
