 <?php
session_start();

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

// Include database connection
require_once 'db.php';

// Get user data
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
$email = $_SESSION['email'];
$role = $_SESSION['role'];

// Get additional user info from database
try {
    $user_data = db_fetch_one("SELECT created_at FROM users WHERE id = ?", [$user_id]);
    $created_at = $user_data['created_at'] ?? "Unknown";
} catch(Exception $e) {
    $created_at = "Unknown";
}

// Handle QR Code Session Creation (Lecturers only)
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create_session']) && $role === 'lecturer') {
    $session_name = trim($_POST['session_name']);
    $end_time = $_POST['end_time'];
    
    // Validate times
    $end_timestamp = strtotime($end_time);
    $current_time = time();
    
    if (!empty($session_name) && !empty($end_time)) {
        if ($end_timestamp <= $current_time) {
            $error = "Session must end in the future.";
        } else {
            try {
                // Generate unique session code
                $session_code = generateSessionCode();
                
                // Format time for database
                $end_time_db = date('Y-m-d H:i:s', $end_timestamp);
                
                // Insert session into database using db helper
                $session_id = db_insert('sessions', [
                    'lecturer_id' => $user_id,
                    'session_name' => $session_name,
                    'session_code' => $session_code,
                    'expires_at' => $end_time_db
                ]);
                
                // Log the activity
                db_insert('activity_logs', [
                    'user_id' => $user_id,
                    'action' => 'SESSION_CREATED',
                    'description' => "Created session: {$session_name} - Expires: " . date('M j, g:i A', $end_timestamp),
                    'ip_address' => $_SERVER['REMOTE_ADDR'],
                    'user_agent' => $_SERVER['HTTP_USER_AGENT']
                ]);
                
                $success = "Session created successfully! QR Code is now available.";
                
            } catch(Exception $e) {
                $error = "Error creating session: " . $e->getMessage();
            }
        }
    } else {
        $error = "Please fill in all required fields.";
    }
}

// Get active sessions for the lecturer
if ($role === 'lecturer') {
    try {
        $active_sessions = db_fetch_all(
            "SELECT * FROM sessions WHERE lecturer_id = ? AND expires_at > NOW() ORDER BY created_at DESC", 
            [$user_id]
        );
    } catch(Exception $e) {
        $active_sessions = [];
    }
} else {
    $active_sessions = [];
}

// Get today's attendance stats
try {
    $today = date('Y-m-d');
    
    // For lecturers: Get attendance for their sessions
    if ($role === 'lecturer') {
        $attendance_data = db_fetch_one(
            "SELECT COUNT(DISTINCT ar.student_id) as attendance_count 
             FROM attendance_records ar 
             JOIN sessions s ON ar.session_id = s.id 
             WHERE s.lecturer_id = ? 
             AND DATE(ar.scanned_at) = ?",
            [$user_id, $today]
        );
        $today_attendance = $attendance_data['attendance_count'] ?? 0;
    } 
    // For students: Get their attendance records
    else {
        $attendance_data = db_fetch_one(
            "SELECT COUNT(*) as attendance_count 
             FROM attendance_records 
             WHERE student_id = ? 
             AND DATE(scanned_at) = ?",
            [$user_id, $today]
        );
        $today_attendance = $attendance_data['attendance_count'] ?? 0;
    }
} catch(Exception $e) {
    $today_attendance = 0;
}

// Get total sessions count for lecturers
if ($role === 'lecturer') {
    try {
        $total_sessions_data = db_fetch_one(
            "SELECT COUNT(*) as total_sessions FROM sessions WHERE lecturer_id = ?", 
            [$user_id]
        );
        $total_sessions = $total_sessions_data['total_sessions'] ?? 0;
    } catch(Exception $e) {
        $total_sessions = 0;
    }
}

// Function to generate unique session code
function generateSessionCode() {
    $random_chars = substr(str_shuffle("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 0, 8);
    return 'SESS_' . $random_chars;
}

// Get recent activity
try {
    if ($role === 'lecturer') {
        $recent_activities = db_fetch_all(
            "SELECT al.*, u.username 
             FROM activity_logs al 
             LEFT JOIN users u ON al.user_id = u.id 
             WHERE al.user_id = ? 
             OR al.description LIKE ? 
             ORDER BY al.created_at DESC 
             LIMIT 5",
            [$user_id, '%session%']
        );
    } else {
        $recent_activities = db_fetch_all(
            "SELECT * FROM activity_logs 
             WHERE user_id = ? 
             ORDER BY created_at DESC 
             LIMIT 5",
            [$user_id]
        );
    }
} catch(Exception $e) {
    $recent_activities = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="dashboard-header">
            <div class="header-left">
                <h1><i class="fas fa-fingerprint"></i> Digital Attendance System</h1>
                <p>Welcome back, <?php echo htmlspecialchars($username); ?>! (<?php echo ucfirst($role); ?>)</p>
            </div>
            <div class="header-right">
                <div class="time-display">
                    <span id="current-date"><?php echo date('l, F j, Y'); ?></span>
                    <span id="current-time"><?php echo date('g:i A'); ?></span>
                </div>
                <a href="logout.php" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="quick-actions">
            <?php if ($role === 'lecturer'): ?>
                <button class="action-btn primary" onclick="openSessionModal()">
                    <i class="fas fa-qrcode"></i>
                    <span>Create QR Session</span>
                </button>
            <?php else: ?>
                <a href="simplescan.php" class="action-btn primary">
                    <i class="fas fa-camera"></i>
                    <span>Scan QR Code</span>
                </a>
            <?php endif; ?>
            
            <a href="attendance_view.php" class="action-btn">
                <i class="fas fa-history"></i>
                <span>Attendance History</span>
            </a>
            
            <?php if ($role === 'lecturer'): ?>
                <a href="reports.php" class="action-btn">
                    <i class="fas fa-chart-bar"></i>
                    <span>Reports</span>
                </a>
            <?php endif; ?>
            
            <a href="profile.php" class="action-btn">
                <i class="fas fa-user"></i>
                <span>My Profile</span>
            </a>
        </div>

        <!-- Success/Error Messages -->
        <?php if (isset($success)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- Main Content Grid -->
        <div class="main-grid">
            <!-- Attendance Stats -->
            <div class="card">
                <div class="card-header">
                    <h2>Today's Summary</h2>
                    <span class="status-badge present">Active</span>
                </div>
                <div class="attendance-stats">
                    <?php if ($role === 'lecturer'): ?>
                        <div class="stat-item">
                            <div class="stat-value"><?php echo count($active_sessions); ?></div>
                            <div class="stat-label">Active Sessions</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value"><?php echo $today_attendance; ?></div>
                            <div class="stat-label">Today's Attendees</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value"><?php echo $total_sessions ?? 0; ?></div>
                            <div class="stat-label">Total Sessions</div>
                        </div>
                    <?php else: ?>
                        <div class="stat-item">
                            <div class="stat-value"><?php echo $today_attendance; ?></div>
                            <div class="stat-label">Classes Attended Today</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value"><?php echo getStudentTotalAttendance($user_id); ?></div>
                            <div class="stat-label">Total Attendance</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value"><?php echo date('g:i A'); ?></div>
                            <div class="stat-label">Current Time</div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- QR Session Management (For Lecturers) -->
            <?php if ($role === 'lecturer'): ?>
                <div class="card">
                    <div class="card-header">
                        <h2>Active QR Sessions</h2>
                        <button class="btn btn-small btn-primary" onclick="openSessionModal()">
                            <i class="fas fa-plus"></i> New Session
                        </button>
                    </div>
                    <div class="sessions-list">
                        <?php if (count($active_sessions) > 0): ?>
                            <?php foreach ($active_sessions as $session): ?>
                                <div class="session-item <?php echo isSessionExpired($session['expires_at']) ? 'expired' : ''; ?>">
                                    <div class="session-info">
                                        <h4><?php echo htmlspecialchars($session['session_name']); ?></h4>
                                        <p class="session-meta">
                                            <strong>Code:</strong> <?php echo htmlspecialchars($session['session_code']); ?>
                                        </p>
                                        <p class="session-time">
                                            <i class="fas fa-clock"></i> 
                                            Expires: <?php echo date('M j, g:i A', strtotime($session['expires_at'])); ?>
                                            <?php if (isSessionExpired($session['expires_at'])): ?>
                                                <span class="expired-badge">Expired</span>
                                            <?php elseif (isSessionActive($session['created_at'], $session['expires_at'])): ?>
                                                <span class="active-badge">Active Now</span>
                                            <?php else: ?>
                                                <span class="upcoming-badge">Active</span>
                                            <?php endif; ?>
                                        </p>
                                    </div>
                                    <div class="session-actions">
                                        <?php if (isSessionActive($session['created_at'], $session['expires_at'])): ?>
                                            <button class="btn btn-small btn-primary" onclick="showQRCode('<?php echo $session['session_code']; ?>', '<?php echo htmlspecialchars($session['session_name']); ?>')">
                                                <i class="fas fa-qrcode"></i> Show QR
                                            </button>
                                        <?php elseif (isSessionExpired($session['expires_at'])): ?>
                                            <span class="expired-badge">Expired</span>
                                        <?php else: ?>
                                            <span class="upcoming-badge">Active</span>
                                        <?php endif; ?>
                                        <a href="attendance.php?id=<?php echo $session['id']; ?>" class="btn btn-small">
                                            <i class="fas fa-eye"></i> View Attendance
                                        </a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-qrcode"></i>
                                <p>No active sessions. Create your first QR session!</p>
                                <button class="btn btn-primary" onclick="openSessionModal()">
                                    <i class="fas fa-plus"></i> Create Session
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php else: ?>
                <!-- Student Specific Content -->
                <div class="card">
                    <div class="card-header">
                        <h2>Quick Attendance</h2>
                    </div>
                    <div class="scan-section">
                        <div class="scan-placeholder">
                            <i class="fas fa-camera"></i>
                            <h3>Scan QR Code</h3>
                            <p>Use the scan button to mark your attendance for active classes</p>
                            <div class="scan-actions">
                                <a href="simplescan.php" class="btn btn-primary">
                                    <i class="fas fa-camera"></i> Scan QR Code
                                </a>
                                <a href="manual_entry.php" class="btn btn-secondary">
                                    <i class="fas fa-keyboard"></i> Enter Code Manually
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Recent Activity -->
            <div class="card">
                <div class="card-header">
                    <h2>Recent Activity</h2>
                </div>
                <div class="activity-list">
                    <?php if (count($recent_activities) > 0): ?>
                        <?php foreach ($recent_activities as $activity): ?>
                            <div class="activity-item">
                                <div class="activity-icon <?php echo strtolower($activity['action']); ?>">
                                    <i class="fas fa-<?php echo getActivityIcon($activity['action']); ?>"></i>
                                </div>
                                <div class="activity-content">
                                    <div class="activity-title"><?php echo htmlspecialchars($activity['action']); ?></div>
                                    <div class="activity-desc"><?php echo htmlspecialchars($activity['description']); ?></div>
                                    <div class="activity-time"><?php echo date('M j, g:i A', strtotime($activity['created_at'])); ?></div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="empty-state">
                            <i class="fas fa-history"></i>
                            <p>No recent activity</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- User Info -->
            <div class="card">
                <div class="card-header">
                    <h2>User Information</h2>
                </div>
                <div class="user-details">
                    <div class="detail-item">
                        <span class="label">User ID:</span>
                        <span class="value">#<?php echo htmlspecialchars($user_id); ?></span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Name:</span>
                        <span class="value"><?php echo htmlspecialchars($username); ?></span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Email:</span>
                        <span class="value"><?php echo htmlspecialchars($email); ?></span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Role:</span>
                        <span class="value role-<?php echo $role; ?>"><?php echo ucfirst($role); ?></span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Member Since:</span>
                        <span class="value"><?php echo date('F j, Y', strtotime($created_at)); ?></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Create Session Modal (Lecturers only) -->
        <?php if ($role === 'lecturer'): ?>
        <div id="sessionModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Create New QR Session</h3>
                    <button class="modal-close" onclick="closeSessionModal()">&times;</button>
                </div>
                <form method="POST" action="" id="sessionForm">
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="session_name">Session Name *</label>
                            <input type="text" id="session_name" name="session_name" required 
                                   placeholder="e.g., Mathematics Class - Week 5"
                                   maxlength="255">
                            <div class="field-error" id="session_name_error"></div>
                        </div>
                        
                        <div class="form-group">
                            <label for="end_time">Expiry Time *</label>
                            <input type="datetime-local" id="end_time" name="end_time" required 
                                   min="<?php echo date('Y-m-d\TH:i'); ?>">
                            <div class="field-error" id="end_time_error"></div>
                            <div class="field-info">QR code will expire at this time</div>
                        </div>
                        
                        <div class="session-preview" id="sessionPreview" style="display: none;">
                            <h4>Session Preview</h4>
                            <div class="preview-content">
                                <p><strong>Session:</strong> <span id="preview_name"></span></p>
                                <p><strong>Expires:</strong> <span id="preview_time"></span></p>
                                <p><strong>Duration:</strong> <span id="preview_duration"></span></p>
                                <p><strong>Session Code:</strong> <span id="preview_code" class="session-code-preview"></span></p>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" onclick="closeSessionModal()">Cancel</button>
                        <button type="submit" name="create_session" class="btn btn-primary" id="createSessionBtn">
                            Create Session
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- QR Code Modal -->
        <div id="qrModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="qrModalTitle">QR Code</h3>
                    <button class="modal-close" onclick="closeQRModal()">&times;</button>
                </div>
                <div class="modal-body" style="text-align: center;">
                    <div id="qrcode"></div>
                    <div class="qr-session-info">
                        <p><strong>Session:</strong> <span id="qrSessionName"></span></p>
                        <p><strong>Session Code:</strong> <span id="qrSessionCode"></span></p>
                        <p><strong>Valid Until:</strong> <span id="qrExpiryTime"></span></p>
                    </div>
                    <p class="qr-instructions">
                        Students should scan this QR code to mark attendance<br>
                        <small>QR code will automatically expire at the session end time</small>
                    </p>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="closeQRModal()">Close</button>
                    <button class="btn btn-primary" onclick="downloadQRCode()">
                        <i class="fas fa-download"></i> Download QR
                    </button>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <script>
        // JavaScript code remains the same as your original dashboard
        // ... (all your existing JavaScript code)
    </script>
</body>
</html>

<?php
// Helper function to get activity icons
function getActivityIcon($action) {
    switch ($action) {
        case 'LOGIN':
            return 'sign-in-alt';
        case 'LOGOUT':
            return 'sign-out-alt';
        case 'ATTENDANCE_MARKED':
            return 'check-circle';
        case 'SESSION_CREATED':
            return 'qrcode';
        case 'FAILED_LOGIN':
            return 'exclamation-triangle';
        default:
            return 'info-circle';
    }
}

// Helper function to check if session is expired
function isSessionExpired($expires_at) {
    return strtotime($expires_at) < time();
}

// Helper function to check if session is currently active
function isSessionActive($created_at, $expires_at) {
    $current_time = time();
    return $current_time >= strtotime($created_at) && $current_time <= strtotime($expires_at);
}

// Helper function to get student total attendance
function getStudentTotalAttendance($student_id) {
    try {
        $data = db_fetch_one(
            "SELECT COUNT(*) as total_attendance FROM attendance_records WHERE student_id = ?", 
            [$student_id]
        );
        return $data['total_attendance'] ?? 0;
    } catch(Exception $e) {
        return 0;
    }
}
?>