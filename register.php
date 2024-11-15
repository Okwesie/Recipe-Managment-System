<?php
header('Content-Type: application/json');

require 'db-connection.php'; //ensuring there is a database connection

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Fetch JSON payload
    $data = json_decode(file_get_contents('php://input'), true);

    $fname = trim($data['firstName']);
    $lname = trim($data['lastName']);
    $email = trim($data['email']);
    $password = trim($data['password']);
    $role = 2;

    // Input Validation
    if (empty($fname) || empty($lname) || empty($email) || empty($password)) {
        die(json_encode(["status" => "error", "message" => "All fields are required."]));
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die(json_encode(["status" => "error", "message" => "Invalid email format."]));
    }

    //checking for duplicate emails 
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->rowCount() > 0) {
        die(json_encode(["status" => "error", "message" => "Email already registered."]));
    }

    // Hashing the password 
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Insert User with timestamps
    $stmt = $pdo->prepare("
        INSERT INTO users (fname, lname, email, password, role, created_at, updated_at) 
        VALUES (?, ?, ?, ?, ?, NOW(), NOW())
    ");
    
    if ($stmt->execute([$fname, $lname, $email, $hashedPassword, $role])) {
        echo json_encode(["status" => "success", "message" => "Registration successful."]);
    } else {
        echo json_encode(["status" => "error", "message" => "Registration failed."]);
    }



}



?>