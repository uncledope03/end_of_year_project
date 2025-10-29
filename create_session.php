 <?php
session_start();

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

// Check if user is a lecturer
if ($_SESSION['role'] !== 'lecturer') {
    $_SESSION['error'] = "Access denied. Only lecturers can create sessions.";
    header("Location: dashboard.php");
    exit();
}

// Include database connection
require_once 'db.php';

// Get user data
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
$email = $_SESSION['email'];
$role = $_SESSION['role'];

$error = '';
$success = '';

// Handle QR Code Session Creation
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create_session'])) {
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
                
                // Insert session into database using your db helper
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
                
                // Store session data for QR generation
                $_SESSION['new_session_code'] = $session_code;
                $_SESSION['new_session_name'] = $session_name;
                
            } catch(PDOException $e) {
                error_log("Session creation error: " . $e->getMessage());
                $error = "Error creating session. Please try again.";
            }
        }
    } else {
        $error = "Please fill in all required fields.";
    }
}

// Function to generate unique session code
function generateSessionCode() {
    $random_chars = substr(str_shuffle("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 0, 8);
    return 'SESS_' . $random_chars;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Session - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="dashboard-header">
            <div class="header-left">
                <h1><i class="fas fa-qrcode"></i> Create QR Session</h1>
                <p>Generate QR codes for student attendance</p>
            </div>
            <div class="header-right">
                <div class="time-display">
                    <span id="current-date"><?php echo date('l, F j, Y'); ?></span>
                    <span id="current-time"><?php echo date('g:i A'); ?></span>
                </div>
                <a href="dashboard.php" class="logout-btn"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="quick-actions">
            <a href="dashboard.php" class="action-btn">
                <i class="fas fa-home"></i>
                <span>Dashboard</span>
            </a>
            <a href="attendance_view.php" class="action-btn">
                <i class="fas fa-history"></i>
                <span>Attendance History</span>
            </a>
            <a href="reports.php" class="action-btn">
                <i class="fas fa-chart-bar"></i>
                <span>Reports</span>
            </a>
        </div>

        <!-- Success/Error Messages -->
        <?php if (!empty($success)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo htmlspecialchars($success); ?>
                <?php if (isset($_SESSION['new_session_code'])): ?>
                    <div style="margin-top: 10px;">
                        <button class="btn btn-small btn-primary" onclick="showQRCode('<?php echo $_SESSION['new_session_code']; ?>', '<?php echo htmlspecialchars($_SESSION['new_session_name']); ?>')">
                            <i class="fas fa-qrcode"></i> Show QR Code
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($error)): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- Main Content Grid -->
        <div class="main-grid">
            <!-- Session Creation Form -->
            <div class="card">
                <div class="card-header">
                    <h2>Create New Session</h2>
                    <i class="fas fa-plus-circle"></i>
                </div>
                <form method="POST" action="" class="session-form" id="sessionForm">
                    <div class="form-group">
                        <label for="session_name">Session Name *</label>
                        <input type="text" id="session_name" name="session_name" required 
                               value="<?php echo isset($_POST['session_name']) ? htmlspecialchars($_POST['session_name']) : ''; ?>"
                               placeholder="e.g., Mathematics Class - Week 5"
                               maxlength="255">
                        <div class="field-info">Enter a descriptive name for this session (3-255 characters)</div>
                    </div>

                    <div class="form-group">
                        <label for="end_time">Expiry Time *</label>
                        <input type="datetime-local" id="end_time" name="end_time" required 
                               min="<?php echo date('Y-m-d\TH:i'); ?>"
                               value="<?php echo isset($_POST['end_time']) ? htmlspecialchars($_POST['end_time']) : ''; ?>">
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

                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" onclick="window.location.href='dashboard.php'">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                        <button type="submit" name="create_session" class="btn btn-primary" id="createSessionBtn">
                            <i class="fas fa-qrcode"></i> Create Session & Generate QR
                        </button>
                    </div>
                </form>
            </div>

            <!-- How It Works -->
            <div class="card">
                <div class="card-header">
                    <h2>How It Works</h2>
                    <i class="fas fa-info-circle"></i>
                </div>
                <div class="session-info">
                    <div class="info-item">
                        <div class="info-icon">
                            <i class="fas fa-qrcode"></i>
                        </div>
                        <div class="info-content">
                            <h4>Create QR Session</h4>
                            <p>Generate a unique QR code for each class session with custom duration.</p>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <div class="info-icon">
                            <i class="fas fa-display"></i>
                        </div>
                        <div class="info-content">
                            <h4>Display QR Code</h4>
                            <p>Show the QR code in your classroom or share it with students.</p>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <div class="info-icon">
                            <i class="fas fa-camera"></i>
                        </div>
                        <div class="info-content">
                            <h4>Students Scan</h4>
                            <p>Students scan the QR code using their phones to mark attendance.</p>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <div class="info-icon">
                            <i class="fas fa-chart-bar"></i>
                        </div>
                        <div class="info-content">
                            <h4>Track Attendance</h4>
                            <p>View real-time attendance records and export reports.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Best Practices -->
            <div class="card">
                <div class="card-header">
                    <h2>Best Practices</h2>
                    <i class="fas fa-lightbulb"></i>
                </div>
                <div class="tips-list">
                    <div class="tip-item">
                        <i class="fas fa-check-circle"></i>
                        <span>Use descriptive session names for easy identification</span>
                    </div>
                    <div class="tip-item">
                        <i class="fas fa-check-circle"></i>
                        <span>Set appropriate duration based on class length</span>
                    </div>
                    <div class="tip-item">
                        <i class="fas fa-check-circle"></i>
                        <span>Refresh QR codes for each new session</span>
                    </div>
                    <div class="tip-item">
                        <i class="fas fa-check-circle"></i>
                        <span>Set expiry time to match your class duration</span>
                    </div>
                </div>
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
    </div>

    <script>
        // Update current time
        function updateCurrentTime() {
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', { 
                hour: 'numeric', 
                minute: '2-digit',
                hour12: true 
            });
            const dateString = now.toLocaleDateString('en-US', { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            });
            
            document.getElementById('current-time').textContent = timeString;
            document.getElementById('current-date').textContent = dateString;
        }
        
        updateCurrentTime();
        setInterval(updateCurrentTime, 1000);

        // Form validation and handling
        document.addEventListener('DOMContentLoaded', function() {
            const sessionForm = document.getElementById('sessionForm');
            const sessionNameInput = document.getElementById('session_name');
            const endTimeInput = document.getElementById('end_time');
            const createButton = document.getElementById('createSessionBtn');
            
            // Set default end time (1 hour from now)
            const now = new Date();
            const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
            endTimeInput.value = formatDateTimeLocal(oneHourLater);
            
            // Real-time validation
            sessionNameInput.addEventListener('input', validateSessionName);
            endTimeInput.addEventListener('change', validateEndTime);
            
            // Update preview on input
            [sessionNameInput, endTimeInput].forEach(input => {
                input.addEventListener('input', updateSessionPreview);
                input.addEventListener('change', updateSessionPreview);
            });
            
            // Form submission
            sessionForm.addEventListener('submit', function(e) {
                if (!validateSessionForm()) {
                    e.preventDefault();
                    return false;
                }
                
                // Show loading state
                const originalText = createButton.innerHTML;
                createButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Session...';
                createButton.disabled = true;
                
                // Re-enable after 5 seconds (safety net)
                setTimeout(() => {
                    createButton.innerHTML = originalText;
                    createButton.disabled = false;
                }, 5000);
            });
            
            // Initial preview update
            updateSessionPreview();
            
            // Auto-focus session name field
            sessionNameInput.focus();
        });

        function validateSessionForm() {
            const sessionName = document.getElementById('session_name').value.trim();
            const endTime = document.getElementById('end_time').value;
            
            let isValid = true;
            
            if (!validateSessionName(sessionName)) {
                isValid = false;
            }
            
            if (!validateEndTime(endTime)) {
                isValid = false;
            }
            
            if (!isValid) {
                showAlert('Please fix the errors in the form', 'error');
            }
            
            return isValid;
        }

        function validateSessionName(sessionName) {
            if (!sessionName) {
                showFieldError('session_name', 'Session name is required');
                return false;
            } else if (sessionName.length < 3) {
                showFieldError('session_name', 'Session name must be at least 3 characters long');
                return false;
            } else if (sessionName.length > 255) {
                showFieldError('session_name', 'Session name is too long (max 255 characters)');
                return false;
            } else {
                clearFieldError('session_name');
                return true;
            }
        }

        function validateEndTime(endTime) {
            if (!endTime) {
                showFieldError('end_time', 'Expiry time is required');
                return false;
            } else if (new Date(endTime) <= new Date()) {
                showFieldError('end_time', 'Expiry time must be in the future');
                return false;
            } else {
                clearFieldError('end_time');
                return true;
            }
        }

        function showFieldError(fieldId, message) {
            const inputElement = document.getElementById(fieldId);
            inputElement.classList.add('error');
            
            // Remove existing error
            const existingError = inputElement.parentNode.querySelector('.field-error');
            if (existingError) {
                existingError.remove();
            }
            
            // Add error message
            const errorElement = document.createElement('div');
            errorElement.className = 'field-error';
            errorElement.textContent = message;
            inputElement.parentNode.appendChild(errorElement);
        }

        function clearFieldError(fieldId) {
            const inputElement = document.getElementById(fieldId);
            inputElement.classList.remove('error');
            
            const existingError = inputElement.parentNode.querySelector('.field-error');
            if (existingError) {
                existingError.remove();
            }
        }

        // Session preview functionality
        function updateSessionPreview() {
            const sessionName = document.getElementById('session_name').value.trim();
            const endTime = document.getElementById('end_time').value;
            
            const preview = document.getElementById('sessionPreview');
            
            if (sessionName && endTime) {
                document.getElementById('preview_name').textContent = sessionName;
                
                const endDate = new Date(endTime);
                const now = new Date();
                document.getElementById('preview_time').textContent = formatDateTime(endDate);
                
                const duration = Math.round((endDate - now) / (1000 * 60));
                document.getElementById('preview_duration').textContent = `${duration} minutes`;
                
                // Generate preview session code
                const randomChars = Math.random().toString(36).substring(2, 10).toUpperCase();
                document.getElementById('preview_code').textContent = `SESS_${randomChars}`;
                
                preview.style.display = 'block';
            } else {
                preview.style.display = 'none';
            }
        }

        // QR Code Modal Functions
        function showQRCode(sessionCode, sessionName) {
            const qrModal = document.getElementById('qrModal');
            const qrModalTitle = document.getElementById('qrModalTitle');
            const qrcodeElement = document.getElementById('qrcode');
            
            // Set modal content
            qrModalTitle.textContent = `QR Code - ${sessionName}`;
            document.getElementById('qrSessionName').textContent = sessionName;
            document.getElementById('qrSessionCode').textContent = sessionCode;
            
            // Clear previous QR code
            qrcodeElement.innerHTML = '';
            
            // Generate QR code URL
            const qrUrl = `${window.location.origin}/simplescan.php?session=${sessionCode}`;
            
            // Generate QR code
            QRCode.toCanvas(qrcodeElement, qrUrl, {
                width: 200,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#FFFFFF'
                }
            }, function(error) {
                if (error) {
                    qrcodeElement.innerHTML = '<p>Error generating QR code</p>';
                    console.error(error);
                }
            });
            
            qrModal.style.display = 'block';
        }

        function closeQRModal() {
            document.getElementById('qrModal').style.display = 'none';
        }

        function downloadQRCode() {
            const canvas = document.querySelector('#qrcode canvas');
            if (canvas) {
                const link = document.createElement('a');
                const sessionName = document.getElementById('qrModalTitle').textContent.replace('QR Code - ', '');
                link.download = `attendance-qr-${sessionName.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.png`;
                link.href = canvas.toDataURL('image/png');
                link.click();
                showAlert('QR code downloaded successfully!', 'success');
            } else {
                showAlert('Error downloading QR code', 'error');
            }
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const qrModal = document.getElementById('qrModal');
            if (event.target === qrModal) {
                closeQRModal();
            }
        }

        // Formatting functions
        function formatDateTimeLocal(date) {
            return date.toISOString().slice(0, 16);
        }

        function formatDateTime(date) {
            return date.toLocaleDateString('en-US', { 
                month: 'short', 
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
        }

        // Alert function
        function showAlert(message, type = 'info') {
            // Remove existing alerts
            const existingAlert = document.querySelector('.custom-alert');
            if (existingAlert) {
                existingAlert.remove();
            }

            const alert = document.createElement('div');
            alert.className = `custom-alert ${type}`;
            
            const icon = type === 'success' ? '✓' : 
                         type === 'error' ? '✗' : 
                         type === 'warning' ? '⚠' : 'ℹ';
            
            alert.innerHTML = `
                <div class="alert-content">
                    <span class="alert-icon">${icon}</span>
                    <span class="alert-message">${message}</span>
                    <button class="alert-close" onclick="this.parentElement.parentElement.remove()">×</button>
                </div>
            `;
            
            document.body.appendChild(alert);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (alert.parentElement) {
                    alert.remove();
                }
            }, 5000);
        }

        // Auto-show QR code if session was just created
        <?php if (isset($_SESSION['new_session_code']) && isset($_SESSION['new_session_name'])): ?>
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(() => {
                showQRCode('<?php echo $_SESSION['new_session_code']; ?>', '<?php echo htmlspecialchars($_SESSION['new_session_name']); ?>');
                // Clear the session variables
                <?php 
                unset($_SESSION['new_session_code']);
                unset($_SESSION['new_session_name']);
                ?>
            }, 500);
        });
        <?php endif; ?>
    </script>
</body>
</html>