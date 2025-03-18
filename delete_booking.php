<?php
session_start();
require 'db.php'; // Ensure the DB connection is correctly included

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['id'])) {
    $id = intval($_POST['id']); // Make sure you sanitize your inputs
    $stmt = $conn->prepare("DELETE FROM bookings WHERE id = :id");
    $stmt->bindParam(':id', $id);
    $success = $stmt->execute();

    if ($success) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Could not delete booking.']);
    }
}
?>