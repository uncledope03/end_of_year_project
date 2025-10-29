 <?php
session_start();

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");

// Check if user is logged in and is a student
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

if ($_SESSION['role'] !== 'student') {
    $_SESSION['error'] = "Access denied. Only students can scan QR codes.";
    header("Location: dashboard.php");
    exit();
}

// Database configuration
$host = '127.0.0.1';
$dbname = 'digital_attendance';
$db_username = 'root';
$db_password = 'matiasdope1234';

$error = '';
$success = '';
$session_data = null;

// Handle QR code scanning
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['session'])) {
    $session_code = trim($_GET['session']);
    $student_id = $_SESSION['user_id'];
    $student_name = $_SESSION['username'];
    
    // Validate session code
    if (empty($session_code)) {
        $error = "Invalid session code.";
    } elseif (strlen($session_code) < 5) {
        $error = "Session code is too short.";
    } else {
        try {
            $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Check if session exists and is active
            $stmt = $pdo->prepare("SELECT s.*, u.username as lecturer_name 
                                  FROM sessions s 
                                  JOIN users u ON s.lecturer_id = u.id 
                                  WHERE s.session_code = :session_code 
                                  AND s.expires_at > NOW() 
                                  AND s.is_active = true");
            $stmt->execute([':session_code' => $session_code]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($session) {
                // Check if already attended
                $stmt = $pdo->prepare("SELECT * FROM attendance_records 
                                      WHERE session_id = :session_id 
                                      AND student_id = :student_id");
                $stmt->execute([':session_id' => $session['id'], ':student_id' => $student_id]);
                $existing_attendance = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$existing_attendance) {
                    // Mark attendance
                    $stmt = $pdo->prepare("INSERT INTO attendance_records (session_id, student_id, ip_address, user_agent) 
                                          VALUES (:session_id, :student_id, :ip_address, :user_agent)");
                    $stmt->execute([
                        ':session_id' => $session['id'],
                        ':student_id' => $student_id,
                        ':ip_address' => $_SERVER['REMOTE_ADDR'],
                        ':user_agent' => $_SERVER['HTTP_USER_AGENT']
                    ]);
                    
                    // Log the activity
                    $activity_stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent) 
                                                  VALUES (:user_id, :action, :description, :ip, :agent)");
                    $activity_stmt->execute([
                        ':user_id' => $student_id,
                        ':action' => 'ATTENDANCE_MARKED',
                        ':description' => "Marked attendance for session: " . $session['session_name'],
                        ':ip' => $_SERVER['REMOTE_ADDR'],
                        ':agent' => $_SERVER['HTTP_USER_AGENT']
                    ]);
                    
                    $success = "Attendance marked successfully for " . $session['session_name'] . "!";
                    $session_data = $session;
                    
                } else {
                    $error = "You have already marked attendance for this session.";
                    $session_data = $session;
                }
            } else {
                $error = "Invalid or expired session QR code. Please ask your lecturer for a new QR code.";
            }
        } catch(PDOException $e) {
            error_log("Attendance scan error: " . $e->getMessage());
            $error = "Error processing attendance. Please try again.";
        }
    }
}

// Get today's attendance count
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
    $today = date('Y-m-d');
    $stmt = $pdo->prepare("SELECT COUNT(*) as count 
                          FROM attendance_records 
                          WHERE student_id = ? 
                          AND DATE(scanned_at) = ?");
    $stmt->execute([$_SESSION['user_id'], $today]);
    $today_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
} catch(PDOException $e) {
    $today_count = 0;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan QR Code - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .scan-page {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .scan-card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            max-width: 800px;
            margin: 0 auto;
        }
        
        .student-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 15px;
            border-left: 4px solid #667eea;
        }
        
        .student-avatar {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5em;
        }
        
        .session-details {
            background: #e8f5e8;
            border-left: 4px solid #2ed573;
            padding: 20px;
            border-radius: 12px;
            margin: 25px 0;
        }
        
        .scan-options {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin: 30px 0;
        }
        
        .qr-scanner-container, .manual-entry {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            border: 2px dashed #ddd;
        }
        
        .camera-image {
            text-align: center;
            margin: 20px 0;
        }
        
        .camera-image img {
            max-width: 200px;
            height: auto;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .manual-form {
            margin-top: 15px;
        }
        
        .quick-stats {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 12px;
            padding: 20px;
            margin-top: 25px;
        }
        
        .stat-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #667eea;
            color: white;
            padding: 10px 15px;
            border-radius: 25px;
            font-weight: 600;
        }
        
        @media (max-width: 768px) {
            .scan-options {
                grid-template-columns: 1fr;
            }
            
            .scan-card {
                padding: 20px;
            }
            
            .camera-image img {
                max-width: 150px;
            }
        }
    </style>
</head>
<body class="scan-page">
    <div class="scan-card">
        <!-- Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px;">
            <div class="logo">
                <i class="fas fa-camera" style="font-size: 2em; color: #667eea;"></i>
                <h1 style="margin: 0; color: #2c3e50;">Mark Attendance</h1>
            </div>
            <a href="dashboard.php" class="btn secondary">
                <i class="fas fa-arrow-left"></i> Back to Dashboard
            </a>
        </div>

        <!-- Student Info -->
        <div class="student-info">
            <div class="student-avatar">
                <i class="fas fa-user-graduate"></i>
            </div>
            <div>
                <h3 style="margin: 0; color: #2c3e50;"><?php echo htmlspecialchars($_SESSION['username']); ?></h3>
                <p style="margin: 5px 0 0 0; color: #7f8c8d;">Student ID: #<?php echo htmlspecialchars($_SESSION['user_id']); ?></p>
            </div>
        </div>

        <!-- Success/Error Messages -->
        <?php if (!empty($error)): ?>
            <div class="alert alert-error" style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #e74c3c;">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Attendance Failed</strong>
                    <p style="margin: 5px 0 0 0;"><?php echo htmlspecialchars($error); ?></p>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!empty($success)): ?>
            <div class="alert alert-success" style="background: #d4edda; color: #155724; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #2ecc71;">
                <i class="fas fa-check-circle"></i>
                <div>
                    <strong>Attendance Successful!</strong>
                    <p style="margin: 5px 0 0 0;"><?php echo htmlspecialchars($success); ?></p>
                </div>
            </div>
        <?php endif; ?>

        <!-- Session Details (if available) -->
        <?php if ($session_data): ?>
            <div class="session-details">
                <h3 style="margin: 0 0 10px 0; color: #27ae60;">
                    <i class="fas fa-chalkboard-teacher"></i> <?php echo htmlspecialchars($session_data['session_name']); ?>
                </h3>
                <p style="margin: 5px 0;"><strong>Lecturer:</strong> <?php echo htmlspecialchars($session_data['lecturer_name']); ?></p>
                <p style="margin: 5px 0;"><strong>Session Code:</strong> <code style="background: #2c3e50; color: white; padding: 2px 8px; border-radius: 4px;"><?php echo htmlspecialchars($session_data['session_code']); ?></code></p>
                <p style="margin: 5px 0;"><strong>Expires:</strong> <?php echo date('g:i A', strtotime($session_data['expires_at'])); ?></p>
            </div>
        <?php endif; ?>

        <!-- Scan Options -->
        <div class="scan-options">
            <!-- QR Code Scanner -->
            <div class="qr-scanner-container">
                <h3><i class="fas fa-qrcode"></i> Scan QR Code</h3>
                <p>Use your camera to scan the QR code displayed by your lecturer</p>
                
                <!-- Google Camera Image -->
                <div class="camera-image">
                    <img src="  data:image/png;base64,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" 
                         alt="Google Camera" 
                         style="width: 200px; height: auto; border-radius: 12px;">
                </div>
                
                <div style="text-align: center; margin-top: 15px;">
                    <p style="color: #5a6c7d; margin-bottom: 15px;">
                        <i class="fas fa-info-circle"></i> 
                        <strong>How to scan:</strong>
                    </p>
                    <ol style="text-align: left; margin: 0; padding-left: 20px; color: #5a6c7d;">
                        <li>Open your phone's camera app</li>
                        <li>Point the camera at the QR code</li>
                        <li>Tap the notification that appears</li>
                        <li>You'll be redirected to mark attendance</li>
                    </ol>
                </div>
            </div>

            <!-- Manual Entry -->
            <div class="manual-entry">
                <h3><i class="fas fa-keyboard"></i> Manual Entry</h3>
                <p>If you have a session code from your lecturer, enter it below:</p>
                
                <form method="GET" action="" class="manual-form">
                    <div class="form-group">
                        <label for="session_code">Session Code</label>
                        <input type="text" id="session_code" name="session" 
                               placeholder="Enter session code (e.g., sess_123abc)" 
                               required
                               pattern="[a-zA-Z0-9_-]+"
                               style="width: 100%; padding: 12px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 16px;">
                    </div>
                    <button type="submit" class="btn primary" style="width: 100%;">
                        <i class="fas fa-paper-plane"></i> Submit Attendance
                    </button>
                </form>
            </div>
        </div>

        <!-- Quick Stats -->
        <div class="quick-stats">
            <h3 style="margin: 0 0 15px 0; color: #856404;">
                <i class="fas fa-chart-line"></i> Today's Attendance
            </h3>
            <div class="stat-badge">
                <i class="fas fa-calendar-check"></i>
                <span><?php echo $today_count; ?> classes attended today</span>
            </div>
        </div>

        <!-- Security Notice -->
        <div style="text-align: center; margin-top: 25px; padding: 15px; background: rgba(102, 126, 234, 0.1); border-radius: 8px;">
            <i class="fas fa-shield-alt" style="color: #667eea;"></i>
            <span style="color: #5a6c7d;">Your attendance is secured with timestamp and IP verification</span>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const sessionCodeInput = document.getElementById('session_code');
            
            // Auto-focus manual entry field
            if (sessionCodeInput) {
                sessionCodeInput.focus();
            }
            
            // Manual form validation
            const manualForm = document.querySelector('.manual-form');
            if (manualForm) {
                manualForm.addEventListener('submit', function(e) {
                    const sessionCode = sessionCodeInput.value.trim();
                    if (!sessionCode) {
                        e.preventDefault();
                        showAlert('Please enter a session code.', 'error');
                        return;
                    }
                    
                    if (sessionCode.length < 5) {
                        e.preventDefault();
                        showAlert('Session code must be at least 5 characters long.', 'error');
                        return;
                    }
                    
                    if (!validateSessionCode(sessionCode)) {
                        e.preventDefault();
                        showAlert('Session code can only contain letters, numbers, hyphens, and underscores.', 'error');
                        return;
                    }
                });
            }
            
            // Auto-redirect to dashboard after successful attendance
            <?php if (!empty($success)): ?>
            setTimeout(() => {
                window.location.href = 'dashboard.php';
            }, 3000);
            <?php endif; ?>
        });
        
        function validateSessionCode(code) {
            const pattern = /^[a-zA-Z0-9_-]+$/;
            return pattern.test(code);
        }
        
        function showAlert(message, type = 'info') {
            // Create alert element
            const alert = document.createElement('div');
            alert.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 8px;
                color: white;
                font-weight: 500;
                z-index: 10000;
                max-width: 300px;
                ${type === 'error' ? 'background: #e74c3c;' : 'background: #3498db;'}
            `;
            alert.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'}"></i>
                    <span>${message}</span>
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