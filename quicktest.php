 <?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

echo "PHP is working!<br>";

$host = '127.0.0.1';
$dbname = 'digital_attendance';
$username = 'root';
$password = 'matiasdope1234';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    echo "✅ DATABASE CONNECTED SUCCESSFULLY!<br>";
    
    // Test if table exists
    $result = $pdo->query("SELECT 1 FROM users LIMIT 1");
    echo "✅ Users table exists!<br>";
    
} catch(PDOException $e) {
    echo "❌ DATABASE ERROR: " . $e->getMessage() . "<br>";
}
?>