  <?php
$host = "127.0.0.1";
$user = "root";
$pass = "matiasdope1234";
$db = "digital_attendance";

try {
    // PDO Connection
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // echo "Database connected successfully!";
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// MySQLi Connection (alternative)
$conn = new mysqli($host, $user, $pass, $db);
if($conn->connect_error){
    die("MySQLi Connection failed: " . $conn->connect_error);
}
?>