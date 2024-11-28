<?php
// Start session
session_start();

// Database connection
$servername = "localhost";
$username = "root"; // Replace with your database username
$password = "";     // Replace with your database password
$dbname = "system_solaire"; // Replace with your database name

$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action']; // sign-up or sign-in

    if ($action === 'sign-up') {
        $name = trim($_POST['name']);
        $email = trim($_POST['email']);
        $password = password_hash(trim($_POST['password']), PASSWORD_BCRYPT);
        $role = $_POST['role'];
        $adminCode = isset($_POST['admin_code']) ? trim($_POST['admin_code']) : '';

        // Check if email already exists
        $checkEmail = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $checkEmail->bind_param("s", $email);
        $checkEmail->execute();
        $checkEmail->store_result();

        if ($checkEmail->num_rows > 0) {
            echo "Email already registered.";
        } else {
            // If admin, verify admin code
            if ($role === 'admin') {
                $validAdminCode = "12345"; // Replace with your admin code
                if ($adminCode !== $validAdminCode) {
                    echo "Invalid admin code.";
                    exit;
                }
            }

            // Insert user into database
            $stmt = $conn->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $name, $email, $password, $role);

            if ($stmt->execute()) {
                echo "Registration successful!";
            } else {
                echo "Error: " . $stmt->error;
            }
        }

        $checkEmail->close();
    } elseif ($action === 'sign-in') {
        $email = trim($_POST['email']);
        $password = trim($_POST['password']);

        // Check user credentials
        $stmt = $conn->prepare("SELECT id, name, password, role FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $name, $hashedPassword, $role);
            $stmt->fetch();

            if (password_verify($password, $hashedPassword)) {
                $_SESSION['user_id'] = $id;
                $_SESSION['name'] = $name;
                $_SESSION['role'] = $role;

                echo "Login successful! Welcome, $name.";
            } else {
                echo "Incorrect password.";
            }
        } else {
            echo "No account found with this email.";
        }

        $stmt->close();
    }
}

$conn->close();
?>

