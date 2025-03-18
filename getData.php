<?php
require 'db.php'; // Include database configuration

$type = $_GET['type'] ?? '';
$search = $_GET['search'] ?? '';
$startDate = $_GET['startDate'] ?? '';
$endDate = $_GET['endDate'] ?? '';

$data = [];

if ($type === 'employees') {
    // Fetch employee data with search filter
    $data = fetchEmployees($conn, $search); 
} elseif ($type === 'buses') {
    // Fetch bus data with search filter
    $data = fetchBuses($conn, $search); 
} elseif ($type === 'bookings') {
    // Fetch booking data filtered by date
    $data = fetchBookingsWithFilters($conn, $startDate, $endDate);
}

echo json_encode($data);

function fetchEmployees($conn, $search = '') {
    $query = "SELECT * FROM employees WHERE id LIKE :search";
    $stmt = $conn->prepare($query);
    $stmt->bindValue(':search', "%$search%");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function fetchBuses($conn, $search = '') {
    $query = "SELECT * FROM buses WHERE no LIKE :search";
    $stmt = $conn->prepare($query);
    $stmt->bindValue(':search', "%$search%");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function fetchBookingsWithFilters($conn, $startDate, $endDate) {
    $query = "SELECT * FROM bookings WHERE 1=1"; // Default query

    if ($startDate) {
        $query .= " AND date >= :startDate";
    }
    if ($endDate) {
        $query .= " AND date <= :endDate";
    }

    $stmt = $conn->prepare($query);

    if ($startDate) {
        $stmt->bindValue(':startDate', $startDate);
    }
    if ($endDate) {
        $stmt->bindValue(':endDate', $endDate);
    }

    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>