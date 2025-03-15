<?php
session_start();
$conn = new mysqli("localhost", "root", "", "registration_db");

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$email = trim($_POST['email']);
$password = $_POST['password'];
$confirm_password = $_POST['confirm_password'];

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['error'] = "Invalid email format!";
    header("Location: index.php");
    exit();
}

if ($password !== $confirm_password) {
    $_SESSION['error'] = "Passwords do not match!";
    header("Location: index.php");
    exit();
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $_SESSION['error'] = "Email already registered!";
    header("Location: index.php");
    exit();
}

$stmt->close();

// Hash password and insert into database
$hashed_password = password_hash($password, PASSWORD_BCRYPT);
$stmt = $conn->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
$stmt->bind_param("ss", $email, $hashed_password);

if ($stmt->execute()) {
    $_SESSION['error'] = "Registration successful!";
} else {
    $_SESSION['error'] = "Something went wrong!";
}

$stmt->close();
$conn->close();
header("Location: index.php");
