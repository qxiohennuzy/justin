<?php
require 'db.php'; // Include your db connection here

if (isset($_GET['id'])) {
    $stmt = $conn->prepare("DELETE FROM buses WHERE id = ?");
    $stmt->execute([$_GET['id']]);
    header("Location: all_buses.php");
}
?>