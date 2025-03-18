<?php
require 'db.php'; // Include your database connection

if (isset($_GET['year']) && isset($_GET['month'])) {
    $year = $_GET['year'];
    $month = $_GET['month'];

    // Prepare SQL statement to count bookings for the specified month
    $stmt = $conn->prepare("SELECT COUNT(*) AS total FROM bookings WHERE MONTH(date) = ? AND YEAR(date) = ?");
    $stmt->execute([$month, $year]);
    
    $totalBookings = $stmt->fetchColumn();

    // Return data as JSON
    echo json_encode(['totalBookings' => $totalBookings]);
} else {
    echo json_encode(['totalBookings' => 0]);
}
?>