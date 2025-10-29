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

// Only lecturers can access reports
if ($_SESSION['role'] !== 'lecturer') {
    $_SESSION['error'] = "Access denied. Only lecturers can view reports.";
    header("Location: dashboard.php");
    exit();
}

// Database configuration
$host = '127.0.0.1';
$dbname = 'digital_attendance';
$db_username = 'root';
$db_password = 'matiasdope1234';

$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Initialize variables
$sessions = [];
$attendance_data = [];
$session_stats = [];
$date_range = [];
$selected_session = $_GET['session'] ?? '';
$selected_date = $_GET['date'] ?? date('Y-m-d');
$selected_student = $_GET['student'] ?? '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $db_username, $db_password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Get all sessions for this lecturer
    $stmt = $pdo->prepare("SELECT id, session_name, session_code, created_at 
                          FROM sessions 
                          WHERE lecturer_id = :lecturer_id 
                          ORDER BY created_at DESC");
    $stmt->execute([':lecturer_id' => $user_id]);
    $sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get date range for filter (last 30 days)
    $date_range = [
        'start' => date('Y-m-d', strtotime('-30 days')),
        'end' => date('Y-m-d')
    ];

    // Build query based on filters
    $query = "SELECT ar.*, u.username, u.email, s.session_name, s.session_code
              FROM attendance_records ar
              JOIN users u ON ar.student_id = u.id
              JOIN sessions s ON ar.session_id = s.id
              WHERE s.lecturer_id = :lecturer_id";

    $params = [':lecturer_id' => $user_id];

    if (!empty($selected_session)) {
        $query .= " AND s.id = :session_id";
        $params[':session_id'] = $selected_session;
    }

    if (!empty($selected_date)) {
        $query .= " AND DATE(ar.scanned_at) = :selected_date";
        $params[':selected_date'] = $selected_date;
    }

    if (!empty($selected_student)) {
        $query .= " AND (u.username LIKE :student OR u.email LIKE :student)";
        $params[':student'] = "%$selected_student%";
    }

    $query .= " ORDER BY ar.scanned_at DESC";

    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $attendance_data = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get session statistics for charts
    $stats_query = "SELECT 
        s.id,
        s.session_name,
        COUNT(DISTINCT ar.student_id) as total_students,
        COUNT(ar.id) as total_scans,
        MIN(ar.scanned_at) as first_scan,
        MAX(ar.scanned_at) as last_scan,
        AVG(TIME_TO_SEC(TIMEDIFF(ar.scanned_at, s.created_at))) as avg_scan_time_sec
    FROM sessions s
    LEFT JOIN attendance_records ar ON s.id = ar.session_id
    WHERE s.lecturer_id = :lecturer_id
    GROUP BY s.id, s.session_name
    ORDER BY s.created_at DESC
    LIMIT 10";

    $stmt = $pdo->prepare($stats_query);
    $stmt->execute([':lecturer_id' => $user_id]);
    $session_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get daily attendance trends for the last 7 days
    $trends_query = "SELECT 
        DATE(ar.scanned_at) as date,
        COUNT(DISTINCT ar.student_id) as student_count,
        COUNT(ar.id) as scan_count
    FROM attendance_records ar
    JOIN sessions s ON ar.session_id = s.id
    WHERE s.lecturer_id = :lecturer_id 
    AND ar.scanned_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    GROUP BY DATE(ar.scanned_at)
    ORDER BY date DESC";

    $stmt = $pdo->prepare($trends_query);
    $stmt->execute([':lecturer_id' => $user_id]);
    $daily_trends = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get student attendance summary
    $student_summary_query = "SELECT 
        u.id,
        u.username,
        u.email,
        COUNT(ar.id) as total_attendance,
        COUNT(DISTINCT DATE(ar.scanned_at)) as days_present,
        MIN(ar.scanned_at) as first_attendance,
        MAX(ar.scanned_at) as last_attendance
    FROM users u
    JOIN attendance_records ar ON u.id = ar.student_id
    JOIN sessions s ON ar.session_id = s.id
    WHERE s.lecturer_id = :lecturer_id
    GROUP BY u.id, u.username, u.email
    ORDER BY total_attendance DESC";

    $stmt = $pdo->prepare($student_summary_query);
    $stmt->execute([':lecturer_id' => $user_id]);
    $student_summary = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch(PDOException $e) {
    error_log("Reports error: " . $e->getMessage());
    $error = "Error loading reports data. Please try again.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports & Analytics - Digital Attendance System</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="dashboard-header">
            <div class="header-left">
                <h1><i class="fas fa-chart-bar"></i> Reports & Analytics</h1>
                <p>Attendance insights and analytics for <?php echo htmlspecialchars($username); ?></p>
            </div>
            <div class="header-right">
                <a href="dashboard.php" class="logout-btn">
                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                </a>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="dashboard-nav">
            <a href="#overview" class="nav-link active" onclick="showReportSection('overview')">
                <i class="fas fa-tachometer-alt"></i> Overview
            </a>
            <a href="#detailed" class="nav-link" onclick="showReportSection('detailed')">
                <i class="fas fa-list"></i> Detailed Report
            </a>
            <a href="#students" class="nav-link" onclick="showReportSection('students')">
                <i class="fas fa-users"></i> Student Analytics
            </a>
            <a href="#export" class="nav-link" onclick="showReportSection('export')">
                <i class="fas fa-download"></i> Export Data
            </a>
        </nav>

        <!-- Filters -->
        <div class="filters-card">
            <div class="card-header">
                <h3><i class="fas fa-filter"></i> Filter Reports</h3>
            </div>
            <form method="GET" action="" class="filter-form">
                <div class="filter-grid">
                    <div class="form-group">
                        <label for="session"><i class="fas fa-qrcode"></i> Session</label>
                        <select id="session" name="session">
                            <option value="">All Sessions</option>
                            <?php foreach ($sessions as $session): ?>
                                <option value="<?php echo $session['id']; ?>" 
                                    <?php echo ($selected_session == $session['id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($session['session_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="date"><i class="fas fa-calendar"></i> Date</label>
                        <input type="date" id="date" name="date" 
                               value="<?php echo htmlspecialchars($selected_date); ?>"
                               min="<?php echo $date_range['start']; ?>" 
                               max="<?php echo $date_range['end']; ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="student"><i class="fas fa-user"></i> Student</label>
                        <input type="text" id="student" name="student" 
                               value="<?php echo htmlspecialchars($selected_student); ?>"
                               placeholder="Search by name or email">
                    </div>
                    
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> Apply Filters
                        </button>
                        <a href="reports.php" class="btn btn-secondary">
                            <i class="fas fa-times"></i> Clear Filters
                        </a>
                    </div>
                </div>
            </form>
        </div>

        <!-- Overview Section -->
        <div id="overview-section" class="section active">
            <!-- Summary Cards -->
            <div class="main-grid">
                <div class="card">
                    <div class="card-header">
                        <h3>Total Sessions</h3>
                        <i class="fas fa-qrcode"></i>
                    </div>
                    <div class="stat-item-large">
                        <div class="stat-value"><?php echo count($sessions); ?></div>
                        <div class="stat-label">Sessions Created</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Total Attendance</h3>
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-item-large">
                        <div class="stat-value"><?php echo count($attendance_data); ?></div>
                        <div class="stat-label">Attendance Records</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Unique Students</h3>
                        <i class="fas fa-user-graduate"></i>
                    </div>
                    <div class="stat-item-large">
                        <?php
                        $unique_students = array_unique(array_column($attendance_data, 'student_id'));
                        $unique_count = count($unique_students);
                        ?>
                        <div class="stat-value"><?php echo $unique_count; ?></div>
                        <div class="stat-label">Students Attended</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Avg. Attendance</h3>
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <div class="stat-item-large">
                        <div class="stat-value">
                            <?php 
                            $avg_attendance = count($sessions) > 0 ? round(count($attendance_data) / count($sessions), 1) : 0;
                            echo $avg_attendance;
                            ?>
                        </div>
                        <div class="stat-label">Per Session</div>
                    </div>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="charts-grid">
                <!-- Session Attendance Chart -->
                <div class="card">
                    <div class="card-header">
                        <h3>Session Attendance</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="sessionChart"></canvas>
                    </div>
                </div>

                <!-- Daily Trends Chart -->
                <div class="card">
                    <div class="card-header">
                        <h3>Daily Attendance Trends</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="dailyTrendsChart"></canvas>
                    </div>
                </div>

                <!-- Student Attendance Chart -->
                <div class="card">
                    <div class="card-header">
                        <h3>Top Students</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="studentChart"></canvas>
                    </div>
                </div>

                <!-- Time Distribution Chart -->
                <div class="card">
                    <div class="card-header">
                        <h3>Scan Time Distribution</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="timeChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Report Section -->
        <div id="detailed-section" class="section">
            <div class="card">
                <div class="card-header">
                    <h3>Detailed Attendance Report</h3>
                    <div class="header-actions">
                        <button class="btn btn-small" onclick="exportToCSV('detailed')">
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
                                    <th>Student</th>
                                    <th>Email</th>
                                    <th>Session</th>
                                    <th>Session Code</th>
                                    <th>Scanned At</th>
                                    <th>IP Address</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($attendance_data as $index => $record): ?>
                                    <tr>
                                        <td><?php echo $index + 1; ?></td>
                                        <td>
                                            <i class="fas fa-user-graduate"></i>
                                            <?php echo htmlspecialchars($record['username']); ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($record['email']); ?></td>
                                        <td><?php echo htmlspecialchars($record['session_name']); ?></td>
                                        <td><code><?php echo htmlspecialchars($record['session_code']); ?></code></td>
                                        <td>
                                            <i class="fas fa-clock"></i>
                                            <?php echo date('M j, Y g:i A', strtotime($record['scanned_at'])); ?>
                                        </td>
                                        <td>
                                            <small><?php echo htmlspecialchars($record['ip_address'] ?? 'N/A'); ?></small>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <div class="empty-state">
                            <i class="fas fa-search"></i>
                            <h4>No Attendance Records Found</h4>
                            <p>Try adjusting your filters to see more results.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Student Analytics Section -->
        <div id="students-section" class="section">
            <div class="card">
                <div class="card-header">
                    <h3>Student Attendance Summary</h3>
                </div>
                <div class="table-container">
                    <?php if (count($student_summary) > 0): ?>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Student</th>
                                    <th>Email</th>
                                    <th>Total Attendance</th>
                                    <th>Days Present</th>
                                    <th>First Attendance</th>
                                    <th>Last Attendance</th>
                                    <th>Attendance Rate</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($student_summary as $student): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-user-graduate"></i>
                                            <?php echo htmlspecialchars($student['username']); ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($student['email']); ?></td>
                                        <td>
                                            <span class="badge"><?php echo $student['total_attendance']; ?></span>
                                        </td>
                                        <td>
                                            <span class="badge"><?php echo $student['days_present']; ?></span>
                                        </td>
                                        <td>
                                            <?php echo $student['first_attendance'] ? date('M j, Y', strtotime($student['first_attendance'])) : 'N/A'; ?>
                                        </td>
                                        <td>
                                            <?php echo $student['last_attendance'] ? date('M j, Y', strtotime($student['last_attendance'])) : 'N/A'; ?>
                                        </td>
                                        <td>
                                            <?php 
                                            $attendance_rate = count($sessions) > 0 ? round(($student['total_attendance'] / count($sessions)) * 100, 1) : 0;
                                            $rate_class = $attendance_rate >= 80 ? 'rate-high' : ($attendance_rate >= 60 ? 'rate-medium' : 'rate-low');
                                            ?>
                                            <span class="attendance-rate <?php echo $rate_class; ?>">
                                                <?php echo $attendance_rate; ?>%
                                            </span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <div class="empty-state">
                            <i class="fas fa-users-slash"></i>
                            <h4>No Student Data</h4>
                            <p>No attendance records found for students.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Export Section -->
        <div id="export-section" class="section">
            <div class="card">
                <div class="card-header">
                    <h3>Export Data</h3>
                    <i class="fas fa-file-export"></i>
                </div>
                <div class="export-options">
                    <div class="export-option">
                        <h4><i class="fas fa-file-csv"></i> CSV Export</h4>
                        <p>Export attendance data in CSV format for spreadsheet analysis.</p>
                        <button class="btn btn-primary" onclick="exportToCSV('full')">
                            <i class="fas fa-download"></i> Export Full Dataset
                        </button>
                        <button class="btn btn-secondary" onclick="exportToCSV('filtered')">
                            <i class="fas fa-download"></i> Export Filtered Data
                        </button>
                    </div>
                    
                    <div class="export-option">
                        <h4><i class="fas fa-chart-bar"></i> Report PDF</h4>
                        <p>Generate a comprehensive PDF report with charts and analytics.</p>
                        <button class="btn btn-primary" onclick="generatePDF()">
                            <i class="fas fa-file-pdf"></i> Generate PDF Report
                        </button>
                    </div>
                    
                    <div class="export-option">
                        <h4><i class="fas fa-print"></i> Print Report</h4>
                        <p>Print the current view with optimized formatting.</p>
                        <button class="btn btn-secondary" onclick="window.print()">
                            <i class="fas fa-print"></i> Print Current View
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Section navigation
        function showReportSection(sectionName) {
            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Show selected section
            document.getElementById(sectionName + '-section').classList.add('active');
            
            // Update nav links
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            event.target.classList.add('active');
        }

        // Initialize charts when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
        });

        function initializeCharts() {
            // Session Attendance Chart
            const sessionCtx = document.getElementById('sessionChart').getContext('2d');
            const sessionLabels = [<?php echo implode(',', array_map(function($stat) { return "'" . htmlspecialchars($stat['session_name']) . "'"; }, $session_stats)); ?>];
            const sessionData = [<?php echo implode(',', array_map(function($stat) { return $stat['total_students']; }, $session_stats)); ?>];
            
            new Chart(sessionCtx, {
                type: 'bar',
                data: {
                    labels: sessionLabels,
                    datasets: [{
                        label: 'Number of Students',
                        data: sessionData,
                        backgroundColor: '#667eea',
                        borderColor: '#5a6fd8',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Students'
                            }
                        }
                    }
                }
            });

            // Daily Trends Chart
            const trendsCtx = document.getElementById('dailyTrendsChart').getContext('2d');
            const trendsLabels = [<?php echo implode(',', array_map(function($trend) { return "'" . date('M j', strtotime($trend['date'])) . "'"; }, array_reverse($daily_trends))); ?>];
            const trendsData = [<?php echo implode(',', array_map(function($trend) { return $trend['student_count']; }, array_reverse($daily_trends))); ?>];
            
            new Chart(trendsCtx, {
                type: 'line',
                data: {
                    labels: trendsLabels,
                    datasets: [{
                        label: 'Daily Attendance',
                        data: trendsData,
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        borderColor: '#667eea',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Students'
                            }
                        }
                    }
                }
            });

            // Student Chart (Top 10)
            const studentCtx = document.getElementById('studentChart').getContext('2d');
            const studentLabels = [<?php echo implode(',', array_slice(array_map(function($student) { return "'" . htmlspecialchars($student['username']) . "'"; }, $student_summary), 0, 10)); ?>];
            const studentData = [<?php echo implode(',', array_slice(array_map(function($student) { return $student['total_attendance']; }, $student_summary), 0, 10)); ?>];
            
            new Chart(studentCtx, {
                type: 'doughnut',
                data: {
                    labels: studentLabels,
                    datasets: [{
                        data: studentData,
                        backgroundColor: [
                            '#667eea', '#764ba2', '#2ed573', '#ffa502', '#ff4757',
                            '#3742fa', '#a4b0be', '#ff6b81', '#7bed9f', '#70a1ff'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });

            // Time Distribution Chart
            const timeCtx = document.getElementById('timeChart').getContext('2d');
            new Chart(timeCtx, {
                type: 'polarArea',
                data: {
                    labels: ['Morning (6AM-12PM)', 'Afternoon (12PM-6PM)', 'Evening (6PM-12AM)', 'Night (12AM-6AM)'],
                    datasets: [{
                        data: [45, 30, 20, 5],
                        backgroundColor: [
                            '#667eea',
                            '#2ed573',
                            '#ffa502',
                            '#ff4757'
                        ]
                    }]
                },
                options: {
                    responsive: true
                }
            });
        }

        // Export functions
        function exportToCSV(type) {
            let csv = [];
            let filename = 'attendance_report';
            
            if (type === 'detailed') {
                // Export detailed table
                const table = document.querySelector('.data-table');
                const headers = [];
                table.querySelectorAll('thead th').forEach(header => {
                    headers.push(header.textContent.trim());
                });
                csv.push(headers.join(','));
                
                table.querySelectorAll('tbody tr').forEach(row => {
                    const rowData = [];
                    row.querySelectorAll('td').forEach(cell => {
                        let text = cell.textContent.trim();
                        text = text.replace(/[#]/g, '').trim();
                        rowData.push(`"${text}"`);
                    });
                    csv.push(rowData.join(','));
                });
                filename = 'detailed_attendance_report';
                
            } else if (type === 'filtered') {
                // Export filtered data
                csv.push('Student,Email,Session,Session Code,Scanned At,IP Address');
                <?php foreach ($attendance_data as $record): ?>
                    csv.push('"<?php echo addslashes($record['username']); ?>","<?php echo addslashes($record['email']); ?>","<?php echo addslashes($record['session_name']); ?>","<?php echo addslashes($record['session_code']); ?>","<?php echo $record['scanned_at']; ?>","<?php echo $record['ip_address'] ?? 'N/A'; ?>"');
                <?php endforeach; ?>
                filename = 'filtered_attendance_data';
                
            } else {
                // Export full dataset
                csv.push('Student,Email,Session,Session Code,Scanned At,IP Address');
                <?php 
                $full_data_stmt = $pdo->prepare("SELECT ar.*, u.username, u.email, s.session_name, s.session_code
                                               FROM attendance_records ar
                                               JOIN users u ON ar.student_id = u.id
                                               JOIN sessions s ON ar.session_id = s.id
                                               WHERE s.lecturer_id = ?
                                               ORDER BY ar.scanned_at DESC");
                $full_data_stmt->execute([$user_id]);
                $full_data = $full_data_stmt->fetchAll(PDO::FETCH_ASSOC);
                foreach ($full_data as $record): ?>
                    csv.push('"<?php echo addslashes($record['username']); ?>","<?php echo addslashes($record['email']); ?>","<?php echo addslashes($record['session_name']); ?>","<?php echo addslashes($record['session_code']); ?>","<?php echo $record['scanned_at']; ?>","<?php echo $record['ip_address'] ?? 'N/A'; ?>"');
                <?php endforeach; ?>
                filename = 'full_attendance_dataset';
            }
            
            // Download CSV
            const csvContent = "data:text/csv;charset=utf-8," + csv.join('\n');
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", filename + "_<?php echo date('Y-m-d'); ?>.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        function generatePDF() {
            alert('PDF generation would be implemented with a library like jsPDF or a server-side solution.');
        }

        // Auto-refresh data every 2 minutes
        setInterval(() => {
            if (!document.hidden) {
                window.location.reload();
            }
        }, 120000);
    </script>
</body>
</html>