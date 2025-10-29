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

require_once 'db.php';
 

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

// Only lecturers can view session attendance
if ($_SESSION['role'] !== 'lecturer') {
    header("Location: dashboard.php");
    exit();
}

// Check if session ID is provided
if (!isset($_GET['session_id'])) {
    header("Location: dashboard.php");
    exit();
}

$session_id = intval($_GET['session_id']);
$lecturer_id = $_SESSION['user_id'];

// Initialize variables
$session = null;
$attendance_list = [];
$total_attendance = 0;

try {
    // Verify the session belongs to this lecturer
    $stmt = $pdo->prepare("SELECT s.*, u.username as lecturer_name 
                          FROM sessions s 
                          JOIN users u ON s.lecturer_id = u.id 
                          WHERE s.id = :session_id 
                          AND s.lecturer_id = :lecturer_id");
    $stmt->execute([':session_id' => $session_id, ':lecturer_id' => $lecturer_id]);
    $session = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$session) {
        die("Session not found or access denied.");
    }

    // Get attendance records for this session
    $stmt = $pdo->prepare("SELECT ar.*, u.username, u.email, u.created_at as user_joined
                          FROM attendance_records ar 
                          JOIN users u ON ar.student_id = u.id 
                          WHERE ar.session_id = :session_id 
                          ORDER BY ar.scanned_at DESC");
    $stmt->execute([':session_id' => $session_id]);
    $attendance_list = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $total_attendance = count($attendance_list);

    // Log the activity
    logActivity($pdo, $lecturer_id, 'VIEW_ATTENDANCE', 
               "Viewed attendance for session: " . $session['session_name'] . " (" . $total_attendance . " attendees)");

} catch (PDOException $e) {
    error_log("Session attendance error: " . $e->getMessage());
    die("System error. Please try again later.");
}

// Function to log activities
function logActivity($pdo, $user_id, $action, $description) {
    try {
        $stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, action, description, ip_address, user_agent) 
                              VALUES (:user_id, :action, :description, :ip, :agent)");
        $stmt->execute([
            ':user_id' => $user_id,
            ':action' => $action,
            ':description' => $description,
            ':ip' => $_SERVER['REMOTE_ADDR'],
            ':agent' => $_SERVER['HTTP_USER_AGENT']
        ]);
    } catch (PDOException $e) {
        error_log("Activity log error: " . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Attendance - Digital Attendance System</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .attendance-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        
        .attendance-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 0.5rem;
        }
        
        .attendance-table {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .attendance-table table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .attendance-table th {
            background: #f8f9fa;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #e9ecef;
        }
        
        .attendance-table td {
            padding: 1rem;
            border-bottom: 1px solid #e9ecef;
        }
        
        .attendance-table tr:hover {
            background: #f8f9fa;
        }
        
        .student-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: #667eea;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: #6c757d;
        }
        
        .empty-state i {
            font-size: 4rem;
            margin-bottom: 1rem;
            color: #dee2e6;
        }
        
        .export-buttons {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .time-badge {
            background: #e9ecef;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: #495057;
        }
        
        @media (max-width: 768px) {
            .attendance-table {
                overflow-x: auto;
            }
            
            .export-buttons {
                flex-direction: column;
            }
        }
    </style>
</head>
<body class="session-attendance">
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <i class="fas fa-users"></i>
                    <h1>Session Attendance</h1>
                </div>
                <nav class="header-nav">
                    <a href="dashboard.php" class="nav-link">
                        <i class="fas fa-tachometer-alt"></i>
                        Dashboard
                    </a>
                    <a href="reports.php" class="nav-link">
                        <i class="fas fa-chart-bar"></i>
                        Reports
                    </a>
                </nav>
            </div>
        </div>

        <!-- Session Header -->
        <div class="attendance-header">
            <div class="header-content">
                <h2><?php echo htmlspecialchars($session['session_name']); ?></h2>
                <p>Session Code: <?php echo htmlspecialchars($session['session_code']); ?></p>
                <p>Created: <?php echo date('F j, Y g:i A', strtotime($session['created_at'])); ?></p>
                <p>Expires: <?php echo date('F j, Y g:i A', strtotime($session['expires_at'])); ?></p>
            </div>
        </div>

        <!-- Quick Stats -->
        <div class="attendance-stats">
            <div class="stat-card">
                <div class="stat-number"><?php echo $total_attendance; ?></div>
                <div class="stat-label">Total Attendees</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">
                    <?php 
                    $unique_students = array_unique(array_column($attendance_list, 'student_id'));
                    echo count($unique_students);
                    ?>
                </div>
                <div class="stat-label">Unique Students</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">
                    <?php
                    if ($total_attendance > 0) {
                        $first_scan = min(array_column($attendance_list, 'scanned_at'));
                        echo date('g:i A', strtotime($first_scan));
                    } else {
                        echo 'N/A';
                    }
                    ?>
                </div>
                <div class="stat-label">First Scan</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">
                    <?php
                    if ($total_attendance > 0) {
                        $last_scan = max(array_column($attendance_list, 'scanned_at'));
                        echo date('g:i A', strtotime($last_scan));
                    } else {
                        echo 'N/A';
                    }
                    ?>
                </div>
                <div class="stat-label">Last Scan</div>
            </div>
        </div>

        <!-- Export Buttons -->
        <div class="export-buttons">
            <button class="btn btn-primary" onclick="printAttendance()">
                <i class="fas fa-print"></i> Print List
            </button>
            <button class="btn btn-success" onclick="exportToCSV()">
                <i class="fas fa-file-csv"></i> Export CSV
            </button>
            <button class="btn btn-secondary" onclick="window.history.back()">
                <i class="fas fa-arrow-left"></i> Go Back
            </button>
        </div>

        <!-- Attendance List -->
        <div class="attendance-table">
            <?php if ($total_attendance > 0): ?>
                <table>
                    <thead>
                        <tr>
                            <th>Student</th>
                            <th>Email</th>
                            <th>Scanned At</th>
                            <th>Record ID</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($attendance_list as $record): ?>
                            <tr>
                                <td>
                                    <div style="display: flex; align-items: center; gap: 10px;">
                                        <div class="student-avatar">
                                            <?php echo strtoupper(substr($record['username'], 0, 1)); ?>
                                        </div>
                                        <div>
                                            <strong><?php echo htmlspecialchars($record['username']); ?></strong>
                                            <div style="font-size: 0.8rem; color: #6c757d;">
                                                ID: #<?php echo htmlspecialchars($record['student_id']); ?>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td><?php echo htmlspecialchars($record['email']); ?></td>
                                <td>
                                    <div class="time-badge">
                                        <?php echo date('M j, g:i A', strtotime($record['scanned_at'])); ?>
                                    </div>
                                </td>
                                <td>#<?php echo htmlspecialchars($record['id']); ?></td>
                                <td>
                                    <code><?php echo htmlspecialchars($record['ip_address']); ?></code>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="empty-state">
                    <i class="fas fa-users-slash"></i>
                    <h3>No Attendance Records</h3>
                    <p>No students have attended this session yet.</p>
                </div>
            <?php endif; ?>
        </div>

        <!-- Footer Info -->
        <div style="margin-top: 2rem; text-align: center; color: #6c757d; font-size: 0.9rem;">
            <p>Report generated on <?php echo date('F j, Y \a\t g:i A'); ?></p>
            <p>Total records: <?php echo $total_attendance; ?></p>
        </div>
    </div>

    <script>
        function printAttendance() {
            window.print();
        }

        function exportToCSV() {
            // Create CSV content
            let csv = 'Student Name,Student Email,Scanned At,Record ID,IP Address\n';
            
            <?php foreach ($attendance_list as $record): ?>
                csv += '<?php echo addslashes($record['username']); ?>,';
                csv += '<?php echo addslashes($record['email']); ?>,';
                csv += '<?php echo date('Y-m-d H:i:s', strtotime($record['scanned_at'])); ?>,';
                csv += '<?php echo $record['id']; ?>,';
                csv += '<?php echo $record['ip_address']; ?>\n';
            <?php endforeach; ?>
            
            // Create and download file
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.setAttribute('hidden', '');
            a.setAttribute('href', url);
            a.setAttribute('download', 'attendance_<?php echo $session['session_code']; ?>_<?php echo date('Y-m-d'); ?>.csv');
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            alert('CSV file downloaded successfully!');
        }

        // Auto-refresh every 30 seconds to get new attendance
        setInterval(() => {
            // You can implement auto-refresh here if needed
            // location.reload();
        }, 30000);
    </script>
</body>
</html>