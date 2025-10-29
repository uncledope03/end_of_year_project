 <?php
session_start();

// Database configuration
$host = '127.0.0.1';
$dbname = 'digital_attendance';
$db_username = 'root';
$db_password = 'matiasdope1234';

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");

// Error messages
$error = '';
$success = '';

// Check if user is already logged in
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header("Location: dashboard.php");
    exit();
}

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $remember_me = isset($_POST['remember_me']);
    
    // Basic validation
    if (empty($email) || empty($password)) {
        $error = "Please fill in all fields";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address";
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters long";
    } else {
        try {
            // Create PDO connection
            $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Prepare SQL statement to prevent SQL injection
            $stmt = $pdo->prepare("SELECT id, username, password, email, role, is_active, login_attempts, last_login FROM users WHERE email = :email");
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            // Check if user exists
            if ($stmt->rowCount() == 1) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Check if account is active
                if (!$user['is_active']) {
                    $error = "This account has been deactivated. Please contact administrator.";
                }
                // Check login attempts (prevent brute force)
                elseif ($user['login_attempts'] >= 5) {
                    $error = "Too many failed login attempts. Account temporarily locked.";
                }
                // Verify password
                elseif (password_verify($password, $user['password'])) {
                    // Password is correct, reset login attempts
                    $resetStmt = $pdo->prepare("UPDATE users SET login_attempts = 0, last_login = NOW() WHERE id = :id");
                    $resetStmt->bindParam(':id', $user['id']);
                    $resetStmt->execute();
                    
                    // Set session variables
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['logged_in'] = true;
                    $_SESSION['login_time'] = time();
                    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                    
                    // Remember me functionality
                    if ($remember_me) {
                        $token = bin2hex(random_bytes(32));
                        $expiry = time() + (30 * 24 * 60 * 60); // 30 days
                        
                        setcookie('remember_token', $token, $expiry, '/', '', true, true);
                        
                        // Store token in database
                        $tokenStmt = $pdo->prepare("UPDATE users SET remember_token = :token, token_expiry = FROM_UNIXTIME(:expiry) WHERE id = :id");
                        $tokenStmt->bindParam(':token', $token);
                        $tokenStmt->bindParam(':expiry', $expiry);
                        $tokenStmt->bindParam(':id', $user['id']);
                        $tokenStmt->execute();
                    }
                    
                    // Log login activity
                    logActivity($pdo, $user['id'], 'LOGIN', 'User logged in successfully');
                    
                    // Redirect to dashboard with success message
                    $_SESSION['success'] = "Welcome back, " . htmlspecialchars($user['username']) . "!";
                    header("Location: dashboard.php");
                    exit();
                    
                } else {
                    // Increment login attempts
                    $attemptsStmt = $pdo->prepare("UPDATE users SET login_attempts = login_attempts + 1, last_attempt = NOW() WHERE id = :id");
                    $attemptsStmt->bindParam(':id', $user['id']);
                    $attemptsStmt->execute();
                    
                    // Log failed attempt
                    logActivity($pdo, $user['id'], 'FAILED_LOGIN', 'Failed login attempt');
                    
                    $error = "Invalid email or password";
                }
            } else {
                // User doesn't exist - generic error for security
                $error = "Invalid email or password";
                
                // Log failed attempt with unknown user
                logActivity($pdo, null, 'FAILED_LOGIN', 'Failed login attempt for non-existent user: ' . $email);
            }
        } catch(PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            $error = "System error. Please try again later.";
        }
    }
}

// Function to log activities
function logActivity($pdo, $user_id, $action, $description) {
    try {
        $stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent) VALUES (:user_id, :action, :description, :ip, :agent)");
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

// Check for success messages from other pages
if (isset($_SESSION['success'])) {
    $success = $_SESSION['success'];
    unset($_SESSION['success']);
}

// Check for logout
if (isset($_GET['logout']) && $_GET['logout'] == 'success') {
    $success = "You have been successfully logged out.";
}

// Check for registration success
if (isset($_GET['registered']) && $_GET['registered'] == 'true') {
    $success = "Registration successful! Please log in with your credentials.";
}

// Check for password reset success
if (isset($_GET['reset']) && $_GET['reset'] == 'success') {
    $success = "Password reset successful! Please log in with your new password.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="login-page">
    <div class="login-container">
        <div class="login-card">
            <!-- Logo Section -->
            <div class="logo-section">
                <div class="logo">
                    <i class="fas fa-fingerprint"></i>
                    <h1>Digital Attendance</h1>
                </div>
                <p class="tagline">Smart QR-Based Attendance System</p>
            </div>

            <!-- Success Messages -->
            <?php if (!empty($success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>

            <!-- Error Messages -->
            <?php if (!empty($error)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <!-- Login Form -->
            <form method="POST" action="" class="login-form" id="loginForm">
                <div class="form-group">
                    <label for="email">
                        <i class="fas fa-envelope"></i>
                        Email Address
                    </label>
                    <input type="email" id="email" name="email" required 
                           value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
                           placeholder="Enter your email address"
                           autocomplete="email">
                    <div class="field-error" id="emailError"></div>
                </div>

                <div class="form-group">
                    <label for="password">
                        <i class="fas fa-lock"></i>
                        Password
                    </label>
                    <div class="password-input-container">
                        <input type="password" id="password" name="password" required 
                               placeholder="Enter your password"
                               autocomplete="current-password">
                        <button type="button" class="toggle-password" id="togglePassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="field-error" id="passwordError"></div>
                </div>

                <div class="form-options">
                    <label class="checkbox-container">
                        <input type="checkbox" name="remember_me" id="remember_me">
                        <span class="checkmark"></span>
                        Remember me for 30 days
                    </label>
                    
                    <a href="forgot-password.php" class="forgot-password">
                        Forgot Password?
                    </a>
                </div>

                <button type="submit" class="btn btn-primary btn-login" id="loginButton">
                    <span class="btn-text">Sign In</span>
                    <div class="btn-loading" style="display: none;">
                        <i class="fas fa-spinner fa-spin"></i>
                        Signing In...
                    </div>
                </button>
            </form>

            <!-- Demo Accounts (for testing) -->
            <div class="demo-accounts">
                <details>
                    <summary>Demo Accounts (Click to expand)</summary>
                    <div class="demo-list">
                        <div class="demo-account">
                            <strong>Lecturer:</strong> lecturer@demo.com / demo123
                        </div>
                        <div class="demo-account">
                            <strong>Student:</strong> student@demo.com / demo123
                        </div>
                    </div>
                </details>
            </div>

            <!-- Registration Link -->
            <div class="register-link">
                <p>Don't have an account? <a href="register.php">Create one here</a></p>
            </div>

            <!-- Additional Links -->
            <div class="additional-links">
                <a href="index.php"><i class="fas fa-home"></i> Home</a>
                <a href="#"><i class="fas fa-shield-alt"></i> Privacy Policy</a>
                <a href="#"><i class="fas fa-question-circle"></i> Help</a>
            </div>
        </div>

        <!-- Security Notice -->
        <div class="security-notice">
            <i class="fas fa-shield-alt"></i>
            <span>Your login is secured with encryption</span>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const loginForm = document.getElementById('loginForm');
            const emailInput = document.getElementById('email');
            const passwordInput = document.getElementById('password');
            const togglePassword = document.getElementById('togglePassword');
            const loginButton = document.getElementById('loginButton');
            const btnText = loginButton.querySelector('.btn-text');
            const btnLoading = loginButton.querySelector('.btn-loading');

            // Toggle password visibility
            togglePassword.addEventListener('click', function() {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
            });

            // Real-time validation
            emailInput.addEventListener('blur', validateEmail);
            passwordInput.addEventListener('blur', validatePassword);

            function validateEmail() {
                const email = emailInput.value.trim();
                const errorElement = document.getElementById('emailError');
                
                if (!email) {
                    showError(emailInput, errorElement, 'Email is required');
                    return false;
                }
                
                if (!isValidEmail(email)) {
                    showError(emailInput, errorElement, 'Please enter a valid email address');
                    return false;
                }
                
                clearError(emailInput, errorElement);
                return true;
            }

            function validatePassword() {
                const password = passwordInput.value;
                const errorElement = document.getElementById('passwordError');
                
                if (!password) {
                    showError(passwordInput, errorElement, 'Password is required');
                    return false;
                }
                
                if (password.length < 6) {
                    showError(passwordInput, errorElement, 'Password must be at least 6 characters');
                    return false;
                }
                
                clearError(passwordInput, errorElement);
                return true;
            }

            function isValidEmail(email) {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return emailRegex.test(email);
            }

            function showError(input, errorElement, message) {
                input.classList.add('error');
                errorElement.textContent = message;
                errorElement.style.display = 'block';
            }

            function clearError(input, errorElement) {
                input.classList.remove('error');
                errorElement.textContent = '';
                errorElement.style.display = 'none';
            }

            // Form submission
            loginForm.addEventListener('submit', function(e) {
                const isEmailValid = validateEmail();
                const isPasswordValid = validatePassword();
                
                if (!isEmailValid || !isPasswordValid) {
                    e.preventDefault();
                    showAlert('Please fix the errors before submitting', 'error');
                    return;
                }

                // Show loading state
                btnText.style.display = 'none';
                btnLoading.style.display = 'block';
                loginButton.disabled = true;

                // Re-enable after 10 seconds (safety net)
                setTimeout(() => {
                    btnText.style.display = 'block';
                    btnLoading.style.display = 'none';
                    loginButton.disabled = false;
                }, 10000);
            });

            // Auto-focus email field
            emailInput.focus();

            // Show demo accounts in development
            const isLocalhost = window.location.hostname === 'localhost' || 
                              window.location.hostname === '127.0.0.1';
            if (isLocalhost) {
                document.querySelector('.demo-accounts').style.display = 'block';
            }
        });

        // Alert function
        function showAlert(message, type = 'info') {
            // Remove existing alerts
            const existingAlert = document.querySelector('.custom-alert');
            if (existingAlert) {
                existingAlert.remove();
            }

            const alert = document.createElement('div');
            alert.className = `custom-alert ${type}`;
            alert.innerHTML = `
                <div class="alert-content">
                    <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'}"></i>
                    <span>${message}</span>
                    <button class="alert-close" onclick="this.parentElement.parentElement.remove()">×</button>
                </div>
            `;
            
            document.body.appendChild(alert);
            
            setTimeout(() => {
                if (alert.parentElement) {
                    alert.remove();
                }
            }, 5000);
        }
    </script>
</body>
</html>