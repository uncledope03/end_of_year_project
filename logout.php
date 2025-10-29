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

// Check if this is a confirmed logout
$confirmed = isset($_GET['confirm']) && $_GET['confirm'] === 'true';

if (!$confirmed && ($_SERVER['REQUEST_METHOD'] !== 'POST')) {
    // Show confirmation page
    showLogoutConfirmation();
    exit();
}

// If confirmed via GET parameter or POST request, proceed with logout
performLogout();

function showLogoutConfirmation() {
    $username = $_SESSION['username'] ?? 'User';
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirm Logout - Digital Attendance System</title>
        <link rel="stylesheet" href="css/style.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            .logout-confirmation {
                max-width: 500px;
                margin: 100px auto;
                padding: 40px;
                text-align: center;
                background: white;
                border-radius: 12px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }
            
            .logout-icon {
                font-size: 4rem;
                color: #667eea;
                margin-bottom: 20px;
            }
            
            .logout-actions {
                display: flex;
                gap: 15px;
                justify-content: center;
                margin-top: 30px;
            }
            
            .btn-logout {
                background: #ff4757;
                color: white;
            }
            
            .btn-logout:hover {
                background: #ff3742;
            }
            
            .btn-cancel {
                background: #a4b0be;
                color: white;
            }
            
            .btn-cancel:hover {
                background: #747d8c;
            }
        </style>
    </head>
    <body class="logout-page">
        <div class="logout-confirmation">
            <div class="logout-icon">
                <i class="fas fa-sign-out-alt"></i>
            </div>
            <h2>Confirm Logout</h2>
            <p>Are you sure you want to log out, <strong><?php echo htmlspecialchars($username); ?></strong>?</p>
            <p class="text-muted">You will need to log in again to access your account.</p>
            
            <form method="POST" action="logout.php" class="logout-actions">
                <button type="button" class="btn btn-cancel" onclick="window.history.back()">
                    <i class="fas fa-arrow-left"></i>
                    Cancel
                </button>
                <button type="submit" class="btn btn-logout">
                    <i class="fas fa-sign-out-alt"></i>
                    Yes, Log Out
                </button>
            </form>
            
            <form method="GET" action="logout.php" style="display: none;">
                <input type="hidden" name="confirm" value="true">
                <button type="submit" id="auto-logout"></button>
            </form>
        </div>

        <script>
            // Auto-logout after 30 seconds of inactivity (optional)
            let inactivityTime = function() {
                let time;
                const resetTimer = () => {
                    clearTimeout(time);
                    time = setTimeout(() => {
                        document.getElementById('auto-logout').click();
                    }, 30000); // 30 seconds
                };

                window.onload = resetTimer;
                document.onmousemove = resetTimer;
                document.onkeypress = resetTimer;
            };

            inactivityTime();
        </script>
    </body>
    </html>
    <?php
}

function performLogout() {
    require_once 'db.php';

    // Log logout activity before destroying session
    if (isset($_SESSION['user_id']) && isset($_SESSION['username'])) {
        try {
            $user_id = $_SESSION['user_id'];
            $username = $_SESSION['username'];
            
            // Log the logout activity
            $stmt = db()->prepare("INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent) 
                                  VALUES (:user_id, :action, :description, :ip, :agent)");
            $stmt->execute([
                ':user_id' => $user_id,
                ':action' => 'LOGOUT',
                ':description' => 'User logged out successfully',
                ':ip' => $_SERVER['REMOTE_ADDR'],
                ':agent' => $_SERVER['HTTP_USER_AGENT']
            ]);
            
            // Clear remember token from database
            $stmt = db()->prepare("UPDATE users SET remember_token = NULL, token_expiry = NULL WHERE id = :id");
            $stmt->execute([':id' => $user_id]);
            
        } catch (PDOException $e) {
            error_log("Logout logging error: " . $e->getMessage());
        }
    }

    // Store username for redirect message
    $username = $_SESSION['username'] ?? 'User';

    // Comprehensive session cleanup
    $_SESSION = array();

    // Destroy session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(), 
            '', 
            [
                'expires' => time() - 42000,
                'path' => $params["path"],
                'domain' => $params["domain"],
                'secure' => $params["secure"],
                'httponly' => $params["httponly"],
                'samesite' => 'Strict'
            ]
        );
    }

    // Clear additional cookies
    clearAdditionalCookies();

    // Destroy session
    session_destroy();
    unset($_SESSION);

    // Security headers
    header_remove('X-Powered-By');
    header("Cache-Control: no-cache, no-store, must-revalidate");
    header("Pragma: no-cache");
    header("Expires: 0");
    header("Clear-Site-Data: \"cache\", \"cookies\", \"storage\", \"executionContexts\"");

    // Redirect with success message
    $redirect_url = "login.php?logout=success&user=" . urlencode($username) . "&time=" . time();
    header("Location: " . $redirect_url);
    exit();
}

function clearAdditionalCookies() {
    $cookies_to_clear = [
        'remember_token',
        'user_preferences',
        'login_attempts',
        'session_data'
    ];

    foreach ($cookies_to_clear as $cookie_name) {
        if (isset($_COOKIE[$cookie_name])) {
            setcookie(
                $cookie_name, 
                '', 
                [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => $_SERVER['HTTP_HOST'],
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]
            );
            unset($_COOKIE[$cookie_name]);
        }
    }
}
?>