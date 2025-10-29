  <?php
session_start();

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

// Database configuration
$host = '127.0.0.1';
$dbname = 'digital_attendance';
$db_username = 'root';
$db_password = 'matiasdope1234';

$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
$role = $_SESSION['role'];

// Initialize variables
$attendance_data = [];
$sessions = [];
$filter_session = $_GET['session'] ?? '';
$filter_date = $_GET['date'] ?? '';
$filter_student = $_GET['student'] ?? '';
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Build query based on role and filters
    if ($role === 'lecturer') {
        // For lecturers: Get all attendance records for their sessions
        $query = "SELECT ar.*, u.username, u.email, s.session_name, s.session_code, s.created_at as session_created
                  FROM attendance_records ar
                  JOIN users u ON ar.student_id = u.id
                  JOIN sessions s ON ar.session_id = s.id
                  WHERE s.lecturer_id = :user_id";
        
        $count_query = "SELECT COUNT(*) 
                       FROM attendance_records ar
                       JOIN sessions s ON ar.session_id = s.id
                       WHERE s.lecturer_id = :user_id";

        $params = [':user_id' => $user_id];
        $count_params = [':user_id' => $user_id];

        // Get sessions for filter dropdown
        $stmt = $pdo->prepare("SELECT id, session_name FROM sessions WHERE lecturer_id = :user_id ORDER BY created_at DESC");
        $stmt->execute([':user_id' => $user_id]);
        $sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);

    } else {
        // For students: Get only their own attendance records
        $query = "SELECT ar.*, s.session_name, s.session_code, s.created_at as session_created, u.username as lecturer_name
                  FROM attendance_records ar
                  JOIN sessions s ON ar.session_id = s.id
                  JOIN users u ON s.lecturer_id = u.id
                  WHERE ar.student_id = :user_id";
        
        $count_query = "SELECT COUNT(*) FROM attendance_records WHERE student_id = :user_id";

        $params = [':user_id' => $user_id];
        $count_params = [':user_id' => $user_id];
    }

    // Apply filters
    if (!empty($filter_session)) {
        $query .= " AND s.id = :session_id";
        $count_query .= " AND s.id = :session_id";
        $params[':session_id'] = $filter_session;
        $count_params[':session_id'] = $filter_session;
    }

    if (!empty($filter_date)) {
        $query .= " AND DATE(ar.scanned_at) = :filter_date";
        $count_query .= " AND DATE(ar.scanned_at) = :filter_date";
        $params[':filter_date'] = $filter_date;
        $count_params[':filter_date'] = $filter_date;
    }

    if (!empty($filter_student) && $role === 'lecturer') {
        $query .= " AND (u.username LIKE :student OR u.email LIKE :student)";
        $count_query .= " AND (u.username LIKE :student OR u.email LIKE :student)";
        $params[':student'] = "%$filter_student%";
        $count_params[':student'] = "%$filter_student%";
    }

    // Add ordering and pagination
    $query .= " ORDER BY ar.scanned_at DESC LIMIT :limit OFFSET :offset";

    // Get total count for pagination
    $stmt = $pdo->prepare($count_query);
    foreach ($count_params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->execute();
    $total_records = $stmt->fetchColumn();
    $total_pages = ceil($total_records / $limit);

    // Get attendance data
    $stmt = $pdo->prepare($query);
    
    // Bind all parameters
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    $stmt->execute();
    $attendance_data = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get attendance statistics
    if ($role === 'student') {
        $stats_stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_attendance,
                COUNT(DISTINCT DATE(scanned_at)) as unique_days,
                MIN(scanned_at) as first_attendance,
                MAX(scanned_at) as last_attendance
            FROM attendance_records 
            WHERE student_id = :user_id
        ");
        $stats_stmt->execute([':user_id' => $user_id]);
        $attendance_stats = $stats_stmt->fetch(PDO::FETCH_ASSOC);
    } else {
        $stats_stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_attendance,
                COUNT(DISTINCT student_id) as unique_students,
                MIN(ar.scanned_at) as first_attendance,
                MAX(ar.scanned_at) as last_attendance
            FROM attendance_records ar
            JOIN sessions s ON ar.session_id = s.id
            WHERE s.lecturer_id = :user_id
        ");
        $stats_stmt->execute([':user_id' => $user_id]);
        $attendance_stats = $stats_stmt->fetch(PDO::FETCH_ASSOC);
    }

} catch(PDOException $e) {
    error_log("Attendance view error: " . $e->getMessage());
    $error = "Error loading attendance data. Please try again.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attendance History - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="dashboard-header">
            <div class="header-left">
                <h1><i class="fas fa-history"></i> Attendance History</h1>
                <p>View and manage attendance records for <?php echo htmlspecialchars($username); ?> (<?php echo ucfirst($role); ?>)</p>
            </div>
            <div class="header-right">
                <a href="dashboard.php" class="logout-btn">
                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                </a>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="main-grid">
            <div class="card">
                <div class="card-header">
                    <h3>Total Attendance</h3>
                    <i class="fas fa-calendar-check"></i>
                </div>
                <div class="stat-item-large">
                    <div class="stat-value"><?php echo $attendance_stats['total_attendance'] ?? 0; ?></div>
                    <div class="stat-label">
                        <?php echo $role === 'student' ? 'Classes Attended' : 'Records Logged'; ?>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>
                        <?php echo $role === 'student' ? 'Unique Days' : 'Unique Students'; ?>
                    </h3>
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-item-large">
                    <div class="stat-value">
                        <?php echo $role === 'student' ? 
                            ($attendance_stats['unique_days'] ?? 0) : 
                            ($attendance_stats['unique_students'] ?? 0); ?>
                    </div>
                    <div class="stat-label">
                        <?php echo $role === 'student' ? 'Different Days' : 'Students Attended'; ?>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>First Attendance</h3>
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-item-large">
                    <div class="stat-value">
                        <?php 
                        if (!empty($attendance_stats['first_attendance'])) {
                            echo date('M j, Y', strtotime($attendance_stats['first_attendance']));
                        } else {
                            echo 'N/A';
                        }
                        ?>
                    </div>
                    <div class="stat-label">Initial Record</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3>Last Attendance</h3>
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-item-large">
                    <div class="stat-value">
                        <?php 
                        if (!empty($attendance_stats['last_attendance'])) {
                            echo date('M j, Y', strtotime($attendance_stats['last_attendance']));
                        } else {
                            echo 'N/A';
                        }
                        ?>
                    </div>
                    <div class="stat-label">Most Recent</div>
                </div>
            </div>
        </div>

        <!-- Filters -->
        <div class="filters-card">
            <div class="card-header">
                <h3><i class="fas fa-filter"></i> Filter Attendance Records</h3>
            </div>
            <form method="GET" action="" class="filter-form">
                <div class="filter-grid">
                    <?php if ($role === 'lecturer' && !empty($sessions)): ?>
                    <div class="form-group">
                        <label for="session"><i class="fas fa-qrcode"></i> Session</label>
                        <select id="session" name="session">
                            <option value="">All Sessions</option>
                            <?php foreach ($sessions as $session): ?>
                                <option value="<?php echo $session['id']; ?>" 
                                    <?php echo ($filter_session == $session['id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($session['session_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <?php endif; ?>
                    
                    <div class="form-group">
                        <label for="date"><i class="fas fa-calendar"></i> Date</label>
                        <input type="date" id="date" name="date" 
                               value="<?php echo htmlspecialchars($filter_date); ?>">
                    </div>
                    
                    <?php if ($role === 'lecturer'): ?>
                    <div class="form-group">
                        <label for="student"><i class="fas fa-user"></i> Student</label>
                        <input type="text" id="student" name="student" 
                               value="<?php echo htmlspecialchars($filter_student); ?>"
                               placeholder="Search by student name or email">
                    </div>
                    <?php endif; ?>
                    
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> Apply Filters
                        </button>
                        <a href="attendance_view.php" class="btn btn-secondary">
                            <i class="fas fa-times"></i> Clear Filters
                        </button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Attendance Records Table -->
        <div class="card">
            <div class="card-header">
                <h3>Attendance Records</h3>
                <div class="header-actions">
                    <button class="btn btn-small" onclick="exportToCSV()">
                        <i class="fas fa-download"></i> Export CSV
                    </button>
                    <button class="btn btn-small" onclick="window.print()">
                        <i class="fas fa-print"></i> Print
                    </button>
                </div>
            </div>
            <div class="table-container">
                <?php if (count($attendance_data) > 0): ?>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <?php if ($role === 'lecturer'): ?>
                                    <th>Student</th>
                                    <th>Email</th>
                                <?php else: ?>
                                    <th>Lecturer</th>
                                <?php endif; ?>
                                <th>Session</th>
                                <th>Session Code</th>
                                <th>Scanned At</th>
                                <th>IP Address</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($attendance_data as $index => $record): ?>
                                <tr>
                                    <td><?php echo $offset + $index + 1; ?></td>
                                    <?php if ($role === 'lecturer'): ?>
                                        <td>
                                            <i class="fas fa-user-graduate"></i>
                                            <?php echo htmlspecialchars($record['username']); ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($record['email']); ?></td>
                                    <?php else: ?>
                                        <td>
                                            <i class="fas fa-chalkboard-teacher"></i>
                                            <?php echo htmlspecialchars($record['lecturer_name']); ?>
                                        </td>
                                    <?php endif; ?>
                                    <td><?php echo htmlspecialchars($record['session_name']); ?></td>
                                    <td><code><?php echo htmlspecialchars($record['session_code']); ?></code></td>
                                    <td>
                                        <i class="fas fa-clock"></i>
                                        <?php echo date('M j, Y g:i A', strtotime($record['scanned_at'])); ?>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars($record['ip_address'] ?? 'N/A'); ?></small>
                                    </td>
                                    <td>
                                        <span class="attendance-rate rate-high">
                                            <i class="fas fa-check-circle"></i> Present
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>

                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                    <div class="pagination">
                        <?php if ($page > 1): ?>
                            <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>" class="btn btn-small">
                                <i class="fas fa-chevron-left"></i> Previous
                            </a>
                        <?php endif; ?>
                        
                        <span class="pagination-info">
                            Page <?php echo $page; ?> of <?php echo $total_pages; ?> 
                            (<?php echo $total_records; ?> total records)
                        </span>
                        
                        <?php if ($page < $total_pages): ?>
                            <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page + 1])); ?>" class="btn btn-small">
                                Next <i class="fas fa-chevron-right"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>

                <?php else: ?>
                    <div class="empty-state">
                        <i class="fas fa-search"></i>
                        <h4>No Attendance Records Found</h4>
                        <p>
                            <?php if ($role === 'student'): ?>
                                You haven't marked attendance for any sessions yet.
                            <?php else: ?>
                                No attendance records found matching your filters.
                            <?php endif; ?>
                        </p>
                        <?php if ($role === 'student'): ?>
                            <a href="simplescan.php" class="btn btn-primary">
                                <i class="fas fa-camera"></i> Scan QR Code
                            </a>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <style>
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            border-top: 1px solid var(--border-color);
            background: var(--light-color);
            flex-wrap: wrap;
            gap: 15px;
        }

        .pagination-info {
            color: var(--gray-color);
            font-weight: 500;
        }

        @media (max-width: 768px) {
            .pagination {
                flex-direction: column;
                text-align: center;
            }
            
            .pagination .btn {
                width: 100%;
                max-width: 200px;
            }
        }
    </style>

    <script>
        // Export to CSV function
        function exportToCSV() {
            let csv = [];
            // Headers
            csv.push('<?php echo $role === 'lecturer' ? 'Student,Email,' : 'Lecturer,'; ?>Session,Session Code,Scanned At,IP Address,Status');
            
            // Data
            <?php foreach ($attendance_data as $record): ?>
                csv.push(
                    '<?php 
                    if ($role === 'lecturer') {
                        echo addslashes($record['username']) . '","' . addslashes($record['email']) . '","';
                    } else {
                        echo addslashes($record['lecturer_name']) . '","';
                    }
                    echo addslashes($record['session_name']) . '","' . 
                    addslashes($record['session_code']) . '","' . 
                    $record['scanned_at'] . '","' . 
                    ($record['ip_address'] ?? 'N/A') . '","Present"';
                    ?>'
                );
            <?php endforeach; ?>
            
            // Download CSV
            const csvContent = "data:text/csv;charset=utf-8," + csv.join('\n');
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "attendance_history_<?php echo date('Y-m-d'); ?>.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Auto-refresh every 2 minutes if on first page
        document.addEventListener('DOMContentLoaded', function() {
            const urlParams = new URLSearchParams(window.location.search);
            const currentPage = parseInt(urlParams.get('page')) || 1;
            
            if (currentPage === 1 && !document.hidden) {
                setInterval(() => {
                    window.location.reload();
                }, 120000);
            }
        });

        // Print optimization
        window.addEventListener('beforeprint', function() {
            document.querySelector('.dashboard-header').style.display = 'none';
            document.querySelector('.filters-card').style.display = 'none';
            document.querySelector('.main-grid').style.display = 'none';
            document.querySelector('.header-actions').style.display = 'none';
        });

        window.addEventListener('afterprint', function() {
            document.querySelector('.dashboard-header').style.display = 'flex';
            document.querySelector('.filters-card').style.display = 'block';
            document.querySelector('.main-grid').style.display = 'grid';
            document.querySelector('.header-actions').style.display = 'flex';
        });
    </script>
</body>
</html>