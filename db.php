 <?php
// Database Configuration Class
class DatabaseConfig {
    const HOST = "127.0.0.1";
    const USER = "root";
    const PASS = "matiasdope1234";
    const DB = "digital_attendance";
    const CHARSET = "utf8mb4";
    const OPTIONS = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_PERSISTENT => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
        PDO::ATTR_TIMEOUT => 30
    ];
}

class DatabaseConnection {
    private static $instance = null;
    private $pdo;
    private $error;

    private function __construct() {
        $this->connect();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function connect() {
        try {
            $dsn = "mysql:host=" . DatabaseConfig::HOST . 
                   ";dbname=" . DatabaseConfig::DB . 
                   ";charset=" . DatabaseConfig::CHARSET;

            $this->pdo = new PDO(
                $dsn, 
                DatabaseConfig::USER, 
                DatabaseConfig::PASS, 
                DatabaseConfig::OPTIONS
            );

            // Set additional attributes
            $this->pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, false);
            
        } catch (PDOException $e) {
            $this->error = $e->getMessage();
            $this->logError($e);
            $this->handleConnectionError($e);
        }
    }

    public function getConnection() {
        // Check if connection is still alive
        if ($this->pdo === null) {
            $this->connect();
        } else {
            try {
                $this->pdo->query('SELECT 1');
            } catch (PDOException $e) {
                $this->connect(); // Reconnect if connection is lost
            }
        }
        
        return $this->pdo;
    }

    public function getError() {
        return $this->error;
    }

    public function isConnected() {
        try {
            if ($this->pdo === null) return false;
            $this->pdo->query('SELECT 1');
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

    private function handleConnectionError($exception) {
        // Log the error
        error_log("Database Connection Failed: " . $exception->getMessage());
        
        // Show user-friendly message in production
        if ($this->isProduction()) {
            die("Database connection temporarily unavailable. Please try again later.");
        } else {
            // Show detailed error in development
            die("Database Connection Error: " . $exception->getMessage() . 
                " [Host: " . DatabaseConfig::HOST . ", DB: " . DatabaseConfig::DB . "]");
        }
    }

    private function logError($exception) {
        $logMessage = date('[Y-m-d H:i:s]') . " DB Error: " . $exception->getMessage() . 
                     " in " . $exception->getFile() . " on line " . $exception->getLine() . 
                     " [IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "]" . PHP_EOL;
        
        file_put_contents(__DIR__ . '/../logs/database_errors.log', $logMessage, FILE_APPEND | LOCK_EX);
    }

    private function isProduction() {
        return $_SERVER['SERVER_NAME'] !== 'localhost' && 
               $_SERVER['SERVER_NAME'] !== '127.0.0.1';
    }

    // Prevent cloning and unserialization
    private function __clone() {}
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}

// Helper functions for common database operations
class DatabaseHelper {
    public static function executeQuery($sql, $params = []) {
        try {
            $pdo = DatabaseConnection::getInstance()->getConnection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            self::logError($e, $sql, $params);
            throw $e;
        }
    }

    public static function fetchAll($sql, $params = []) {
        $stmt = self::executeQuery($sql, $params);
        return $stmt->fetchAll();
    }

    public static function fetchOne($sql, $params = []) {
        $stmt = self::executeQuery($sql, $params);
        return $stmt->fetch();
    }

    public static function insert($table, $data) {
        $columns = implode(', ', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));
        
        $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
        $stmt = self::executeQuery($sql, $data);
        
        return DatabaseConnection::getInstance()->getConnection()->lastInsertId();
    }

    public static function update($table, $data, $where, $whereParams = []) {
        $setParts = [];
        foreach (array_keys($data) as $column) {
            $setParts[] = "$column = :$column";
        }
        $setClause = implode(', ', $setParts);
        
        $sql = "UPDATE $table SET $setClause WHERE $where";
        $params = array_merge($data, $whereParams);
        
        $stmt = self::executeQuery($sql, $params);
        return $stmt->rowCount();
    }

    public static function delete($table, $where, $params = []) {
        $sql = "DELETE FROM $table WHERE $where";
        $stmt = self::executeQuery($sql, $params);
        return $stmt->rowCount();
    }

    public static function beginTransaction() {
        return DatabaseConnection::getInstance()->getConnection()->beginTransaction();
    }

    public static function commit() {
        return DatabaseConnection::getInstance()->getConnection()->commit();
    }

    public static function rollBack() {
        return DatabaseConnection::getInstance()->getConnection()->rollBack();
    }

    private static function logError($exception, $sql = '', $params = []) {
        $logMessage = date('[Y-m-d H:i:s]') . " DB Query Error: " . $exception->getMessage() . 
                     " [SQL: " . $sql . "]" . 
                     " [Params: " . json_encode($params) . "]" . 
                     " in " . $exception->getFile() . " on line " . $exception->getLine() . PHP_EOL;
        
        $logDir = __DIR__ . '/../logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        file_put_contents($logDir . '/database_queries.log', $logMessage, FILE_APPEND | LOCK_EX);
    }
}

// Initialize database connection
try {
    $db = DatabaseConnection::getInstance();
    $pdo = $db->getConnection();
    
    // Test connection
    if (!$db->isConnected()) {
        throw new PDOException("Failed to establish database connection");
    }
    
} catch (Exception $e) {
    error_log("Database initialization failed: " . $e->getMessage());
    
    // Don't expose errors in production
    if ($_SERVER['SERVER_NAME'] === 'localhost' || $_SERVER['SERVER_NAME'] === '127.0.0.1') {
        die("Database initialization error: " . $e->getMessage());
    } else {
        die("System temporarily unavailable. Please try again later.");
    }
}

// Create necessary tables if they don't exist (for development)
function createTablesIfNotExist($pdo) {
    $tables = [
        "users" => "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('student', 'lecturer', 'admin') DEFAULT 'student',
            is_active BOOLEAN DEFAULT TRUE,
            login_attempts INT DEFAULT 0,
            last_attempt DATETIME NULL,
            last_login DATETIME NULL,
            remember_token VARCHAR(100) NULL,
            token_expiry DATETIME NULL,
            verification_token VARCHAR(100) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username),
            INDEX idx_role (role)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "sessions" => "CREATE TABLE IF NOT EXISTS sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lecturer_id INT NOT NULL,
            session_name VARCHAR(255) NOT NULL,
            session_code VARCHAR(50) UNIQUE NOT NULL,
            qr_code_data TEXT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (lecturer_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_lecturer_id (lecturer_id),
            INDEX idx_session_code (session_code),
            INDEX idx_expires_at (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "attendance_records" => "CREATE TABLE IF NOT EXISTS attendance_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            session_id INT NOT NULL,
            student_id INT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45) NULL,
            user_agent TEXT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE KEY unique_attendance (session_id, student_id),
            INDEX idx_session_id (session_id),
            INDEX idx_student_id (student_id),
            INDEX idx_scanned_at (scanned_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        "activity_logs" => "CREATE TABLE IF NOT EXISTS activity_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            action VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            ip_address VARCHAR(45) NULL,
            user_agent TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_id (user_id),
            INDEX idx_action (action),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    ];

    foreach ($tables as $tableName => $createSQL) {
        try {
            $pdo->exec($createSQL);
        } catch (PDOException $e) {
            error_log("Failed to create table $tableName: " . $e->getMessage());
        }
    }
}

// Auto-create tables in development
if (($_SERVER['SERVER_NAME'] ?? '') === 'localhost' || ($_SERVER['SERVER_NAME'] ?? '') === '127.0.0.1') {
    createTablesIfNotExist($pdo);
}

// Global database helper functions
function db() {
    return DatabaseConnection::getInstance()->getConnection();
}

function db_query($sql, $params = []) {
    return DatabaseHelper::executeQuery($sql, $params);
}

function db_fetch_all($sql, $params = []) {
    return DatabaseHelper::fetchAll($sql, $params);
}

function db_fetch_one($sql, $params = []) {
    return DatabaseHelper::fetchOne($sql, $params);
}

function db_insert($table, $data) {
    return DatabaseHelper::insert($table, $data);
}

function db_update($table, $data, $where, $whereParams = []) {
    return DatabaseHelper::update($table, $data, $where, $whereParams);
}

function db_delete($table, $where, $params = []) {
    return DatabaseHelper::delete($table, $where, $params);
}
?>