 <?php
// Add these lines at the VERY TOP of your file
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

session_start();

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");

// Database configuration
$host = '127.0.0.1';
$dbname = 'digital_attendance';
$db_username = 'root';
$db_password = 'matiasdope1234';

// Error and success messages
$error = '';
$success = '';

// Check if user is already logged in
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header("Location: dashboard.php");
    exit();
}

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $role = isset($_POST['role']) ? $_POST['role'] : 'student'; // Default role
    $agree_terms = isset($_POST['agree_terms']);
    
    // Enhanced validation
    $errors = [];
    
    // Username validation
    if (empty($username)) {
        $errors['username'] = "Username is required";
    } elseif (strlen($username) < 3) {
        $errors['username'] = "Username must be at least 3 characters long";
    } elseif (strlen($username) > 30) {
        $errors['username'] = "Username must not exceed 30 characters";
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        $errors['username'] = "Username can only contain letters, numbers, and underscores";
    }
    
    // Email validation
    if (empty($email)) {
        $errors['email'] = "Email address is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Please enter a valid email address";
    } elseif (strlen($email) > 100) {
        $errors['email'] = "Email address is too long";
    }
    
    // Password validation
    if (empty($password)) {
        $errors['password'] = "Password is required";
    } else {
        if (strlen($password) < 6) {
            $errors['password'] = "Password must be at least 6 characters long";
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors['password'] = "Password must contain at least one uppercase letter";
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors['password'] = "Password must contain at least one lowercase letter";
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors['password'] = "Password must contain at least one number";
        }
    }
    
    // Confirm password validation
    if (empty($confirm_password)) {
        $errors['confirm_password'] = "Please confirm your password";
    } elseif ($password !== $confirm_password) {
        $errors['confirm_password'] = "Passwords do not match";
    }
    
    // Terms agreement validation
    if (!$agree_terms) {
        $errors['agree_terms'] = "You must agree to the terms and conditions";
    }
    
    // Role validation
    if (!in_array($role, ['student', 'lecturer'])) {
        $errors['role'] = "Please select a valid role";
    }
    
    // If no validation errors, proceed with registration
    if (empty($errors)) {
        try {
            // Create PDO connection
            $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Check if email already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                $errors['email'] = "Email address is already registered";
            } else {
                // Check if username already exists
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username");
                $stmt->bindParam(':username', $username);
                $stmt->execute();
                
                if ($stmt->rowCount() > 0) {
                    $errors['username'] = "Username is already taken";
                } else {
                    // Hash password with cost factor 12
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
                    
                    // Generate verification token
                    $verification_token = bin2hex(random_bytes(32));
                    $token_expiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
                    
                    // Insert new user
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, password, role, verification_token, token_expiry, created_at) 
                                          VALUES (:username, :email, :password, :role, :token, :token_expiry, NOW())");
                    $stmt->bindParam(':username', $username);
                    $stmt->bindParam(':email', $email);
                    $stmt->bindParam(':password', $hashed_password);
                    $stmt->bindParam(':role', $role);
                    $stmt->bindParam(':token', $verification_token);
                    $stmt->bindParam(':token_expiry', $token_expiry);
                    
                    if ($stmt->execute()) {
                        $user_id = $pdo->lastInsertId();
                        
                        // Log registration activity
                        logActivity($pdo, $user_id, 'REGISTRATION', 'User registered successfully');
                        
                        // Send verification email (simulated)
                        if (sendVerificationEmail($email, $username, $verification_token)) {
                            $success = "Registration successful! A verification email has been sent to your email address.";
                        } else {
                            $success = "Registration successful! You can now <a href='login.php' style='color: #667eea; font-weight: 500;'>login</a>.";
                        }
                        
                        // Clear form data
                        $_POST = [];
                    } else {
                        $error = "Registration failed. Please try again.";
                    }
                }
            }
        } catch(PDOException $e) {
            error_log("Registration error: " . $e->getMessage());
            $error = "System error. Please try again later.";
        }
    } else {
        // Combine field errors into a general error message
        $error = "Please fix the errors below";
    }
}

// Function to log activities
function logActivity($pdo, $user_id, $action, $description) {
    try {
        $stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent) 
                              VALUES (:user_id, :action, :description, :ip, :agent)");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':action', $action);
        $stmt->bindParam(':description', $description);
        $stmt->bindParam(':ip', $_SERVER['REMOTE_ADDR']);
        $stmt->bindParam(':agent', $_SERVER['HTTP_USER_AGENT']);
        $stmt->execute();
    } catch (PDOException $e) {
        error_log("Activity log error: " . $e->getMessage());
    }
}

// Function to send verification email (simulated)
function sendVerificationEmail($email, $username, $token) {
    // In a real application, you would send an actual email
    // For now, we'll just log it
    $verification_link = "http://yourdomain.com/verify.php?token=" . $token;
    error_log("Verification email would be sent to: $email with link: $verification_link");
    
    // Return true to simulate successful email sending
    return false; // Set to false to skip email for demo purposes
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="register-page">
    <div class="register-container">
        <div class="register-card">
            <!-- Logo Section -->
            <div class="logo-section">
                <div class="logo">
                    <i class="fas fa-user-plus"></i>
                    <h1>Create Account</h1>
                </div>
                <p class="tagline">Join our digital attendance system</p>
            </div>

            <!-- Error Messages -->
            <?php if (!empty($error) && empty($errors)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <!-- Success Messages -->
            <?php if (!empty($success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo $success; ?>
                </div>
            <?php endif; ?>

            <!-- Registration Form -->
            <form method="POST" action="" class="register-form" id="registerForm">
                <!-- Role Selection -->
                <div class="form-group">
                    <label for="role">
                        <i class="fas fa-user-tag"></i>
                        I am a:
                    </label>
                    <div class="role-selection">
                        <label class="role-option">
                            <input type="radio" name="role" value="student" <?php echo (isset($_POST['role']) && $_POST['role'] == 'student') ? 'checked' : 'checked'; ?>>
                            <div class="role-card">
                                <i class="fas fa-graduation-cap"></i>
                                <span>Student</span>
                                <small>Scan QR codes to mark attendance</small>
                            </div>
                        </label>
                        <label class="role-option">
                            <input type="radio" name="role" value="lecturer" <?php echo (isset($_POST['role']) && $_POST['role'] == 'lecturer') ? 'checked' : ''; ?>>
                            <div class="role-card">
                                <i class="fas fa-chalkboard-teacher"></i>
                                <span>Lecturer</span>
                                <small>Create sessions and generate QR codes</small>
                            </div>
                        </label>
                    </div>
                    <?php if (isset($errors['role'])): ?>
                        <div class="field-error"><?php echo htmlspecialchars($errors['role']); ?></div>
                    <?php endif; ?>
                </div>

                <!-- Username Field -->
                <div class="form-group">
                    <label for="username">
                        <i class="fas fa-user"></i>
                        Username
                    </label>
                    <input type="text" id="username" name="username" required 
                           value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                           minlength="3" maxlength="30"
                           placeholder="Choose a username"
                           autocomplete="username"
                           class="<?php echo isset($errors['username']) ? 'error' : ''; ?>">
                    <?php if (isset($errors['username'])): ?>
                        <div class="field-error"><?php echo htmlspecialchars($errors['username']); ?></div>
                    <?php endif; ?>
                    <div class="field-info">3-30 characters, letters, numbers, and underscores only</div>
                </div>

                <!-- Email Field -->
                <div class="form-group">
                    <label for="email">
                        <i class="fas fa-envelope"></i>
                        Email Address
                    </label>
                    <input type="email" id="email" name="email" required 
                           value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
                           placeholder="Enter your email address"
                           autocomplete="email"
                           class="<?php echo isset($errors['email']) ? 'error' : ''; ?>">
                    <?php if (isset($errors['email'])): ?>
                        <div class="field-error"><?php echo htmlspecialchars($errors['email']); ?></div>
                    <?php endif; ?>
                </div>

                <!-- Password Field -->
                <div class="form-group">
                    <label for="password">
                        <i class="fas fa-lock"></i>
                        Password
                    </label>
                    <div class="password-input-container">
                        <input type="password" id="password" name="password" required 
                               placeholder="Create a password"
                               autocomplete="new-password"
                               minlength="6"
                               class="<?php echo isset($errors['password']) ? 'error' : ''; ?>">
                        <button type="button" class="toggle-password" id="togglePassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <?php if (isset($errors['password'])): ?>
                        <div class="field-error"><?php echo htmlspecialchars($errors['password']); ?></div>
                    <?php endif; ?>
                    
                    <!-- Password Strength Meter -->
                    <div class="password-strength">
                        <div class="strength-labels">
                            <span>Password Strength:</span>
                            <span id="strengthText">None</span>
                        </div>
                        <div class="strength-bar">
                            <div class="strength-indicator" id="passwordStrength"></div>
                        </div>
                    </div>
                    
                    <!-- Password Requirements -->
                    <div class="password-requirements">
                        <h4>Password must contain:</h4>
                        <ul>
                            <li id="req-length"><i class="fas fa-circle"></i> At least 6 characters</li>
                            <li id="req-uppercase"><i class="fas fa-circle"></i> One uppercase letter</li>
                            <li id="req-lowercase"><i class="fas fa-circle"></i> One lowercase letter</li>
                            <li id="req-number"><i class="fas fa-circle"></i> One number</li>
                        </ul>
                    </div>
                </div>

                <!-- Confirm Password Field -->
                <div class="form-group">
                    <label for="confirm_password">
                        <i class="fas fa-lock"></i>
                        Confirm Password
                    </label>
                    <div class="password-input-container">
                        <input type="password" id="confirm_password" name="confirm_password" required 
                               placeholder="Confirm your password"
                               autocomplete="new-password"
                               class="<?php echo isset($errors['confirm_password']) ? 'error' : ''; ?>">
                        <button type="button" class="toggle-password" id="toggleConfirmPassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <?php if (isset($errors['confirm_password'])): ?>
                        <div class="field-error"><?php echo htmlspecialchars($errors['confirm_password']); ?></div>
                    <?php endif; ?>
                    <div id="passwordMatch" class="password-match"></div>
                </div>

                <!-- Terms Agreement -->
                <div class="form-group terms-group">
                    <label class="checkbox-container">
                        <input type="checkbox" name="agree_terms" id="agree_terms" 
                               <?php echo isset($_POST['agree_terms']) ? 'checked' : ''; ?>>
                        <span class="checkmark"></span>
                        I agree to the <a href="terms.php" target="_blank">Terms of Service</a> and <a href="privacy.php" target="_blank">Privacy Policy</a>
                    </label>
                    <?php if (isset($errors['agree_terms'])): ?>
                        <div class="field-error"><?php echo htmlspecialchars($errors['agree_terms']); ?></div>
                    <?php endif; ?>
                </div>

                <!-- Submit Button -->
                <button type="submit" class="btn btn-primary btn-register" id="submitBtn">
                    <span class="btn-text">Create Account</span>
                    <div class="btn-loading" style="display: none;">
                        <i class="fas fa-spinner fa-spin"></i>
                        Creating Account...
                    </div>
                </button>
            </form>

            <!-- Login Link -->
            <div class="login-link">
                <p>Already have an account? <a href="login.php">Sign in here</a></p>
            </div>

            <!-- Additional Links -->
            <div class="additional-links">
                <a href="index.php"><i class="fas fa-home"></i> Home</a>
                <a href="#"><i class="fas fa-shield-alt"></i> Privacy Policy</a>
                <a href="#"><i class="fas fa-question-circle"></i> Help Center</a>
            </div>
        </div>

        <!-- Security Notice -->
        <div class="security-notice">
            <i class="fas fa-shield-alt"></i>
            <span>Your data is protected with industry-standard encryption</span>
        </div>
    </div>

    <script src="script.js"></script>
    <script>
        // Enhanced registration form validation
        document.addEventListener('DOMContentLoaded', function() {
            initializeRegistrationValidation();
        });
    </script>
</body>
</html>