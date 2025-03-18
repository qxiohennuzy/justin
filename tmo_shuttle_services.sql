-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 06, 2025 at 02:13 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `tmo_shuttle_services`
--

-- --------------------------------------------------------

--
-- Table structure for table `bookings`
--

CREATE TABLE `bookings` (
  `id` int(11) NOT NULL,
  `busNo` varchar(50) NOT NULL,
  `driverName` varchar(100) NOT NULL,
  `in_out` enum('In','Out') NOT NULL,
  `company` varchar(100) NOT NULL,
  `date` date NOT NULL,
  `time` time NOT NULL,
  `seatNo` varchar(10) NOT NULL,
  `price` decimal(10,2) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `bookings`
--

INSERT INTO `bookings` (`id`, `busNo`, `driverName`, `in_out`, `company`, `date`, `time`, `seatNo`, `price`) VALUES
(1, '888181', 'j.magalona', 'Out', 'BROTHER ST. TOMAS', '2025-03-18', '21:08:00', '1231', 231.00);

-- --------------------------------------------------------

--
-- Table structure for table `buses`
--

CREATE TABLE `buses` (
  `id` int(11) NOT NULL,
  `no` varchar(50) NOT NULL,
  `plateNumber` varchar(20) NOT NULL,
  `myFileNo` varchar(50) NOT NULL,
  `motorNo` varchar(50) NOT NULL,
  `make` varchar(50) NOT NULL,
  `chasisNo` varchar(50) NOT NULL,
  `remarks` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `buses`
--

INSERT INTO `buses` (`id`, `no`, `plateNumber`, `myFileNo`, `motorNo`, `make`, `chasisNo`, `remarks`) VALUES
(1, '213', '213', '213', '231', '213', '213', '213');

-- --------------------------------------------------------

--
-- Table structure for table `employees`
--

CREATE TABLE `employees` (
  `id` int(11) NOT NULL,
  `firstName` varchar(50) NOT NULL,
  `lastName` varchar(50) NOT NULL,
  `mobile` varchar(15) NOT NULL,
  `licenseExpiration` date NOT NULL,
  `address` varchar(255) NOT NULL,
  `assignedBus` varchar(50) DEFAULT NULL,
  `isActive` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `employees`
--

INSERT INTO `employees` (`id`, `firstName`, `lastName`, `mobile`, `licenseExpiration`, `address`, `assignedBus`, `isActive`) VALUES
(1, 'wqe', 'lquido', '656', '2025-03-06', 'wqewqeq', 'Bus 2', 1);

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','staff') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `role`) VALUES
(1, 'qwer', '$2y$10$lewG9DZl79vajaSbA4KXxOi9N9qQ4UUUu.W4/WiOoIJK75qm.Ntg2', 'admin'),
(2, 'qw', '$2y$10$cOp/cyOd4s6HH01s2pUIW.CLRz2ttPDu0xvBdE7I6MbCNHMozuoqu', 'admin'),
(3, 'axiohennizy@gmail.com', '$2y$10$gHgq69zSEH37tZ5bAXT4vurqnOtssA9LjgKjjN.IwLNSiioi218Ga', 'staff'),
(4, 'jjliquido', '$2y$10$bDqlJf7tKMMcReuNTegFdOGQmO1AOh8DygfaCCh7M02v.wPKJODuq', 'admin'),
(5, 'KolKol', '$2y$10$FkIWTjnYHkfgDePn8MOec.2qYR/a3iulyk7YyqRajg3g1Cq8yFT6S', 'staff'),
(6, 'KolKol', '$2y$10$O5ojxlLixEOR5jrZk1ta9eGAPVgKabenkXQGkHSRQrcd/5F7Fa.z.', 'staff'),
(7, 'demihell797@gmail.com', '$2y$10$x3RBzwQ6XTXKwxnjGeG83ey5ZS29Fdh7mJ4pwR2BAc9KoYoGNBtnO', 'admin'),
(8, '1213', '$2y$10$.fF4jwPaXJZbrI34cPrij.M5T6tMggPObLKH/eRlJXMziWDCMZfxO', 'admin'),
(9, '12134', '$2y$10$TaBVzyiEHZSH/zcJKhvT/up05jbrT7gDOB7V.G/aB7uL5bZiVL/1C', 'admin'),
(10, '1', '$2y$10$ZgkrpLplbNw16bJ174Jmxu/T1TD28fn8UIhq/Lmw5frj4z6oEzIHi', 'admin'),
(11, '1', '$2y$10$JgTy4D4zPcwlVJk9XFt6qOtkc.4zZR10HmzqgzEKd0h22LK2SBOM6', 'admin'),
(12, 'wew', '$2y$10$Atb9LJUeDhAO3Z31.TeMp.eQnVjqgeOavz4MIRaRsnKI83LvbDIk2', 'admin');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `bookings`
--
ALTER TABLE `bookings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `buses`
--
ALTER TABLE `buses`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employees`
--
ALTER TABLE `employees`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `bookings`
--
ALTER TABLE `bookings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `buses`
--
ALTER TABLE `buses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `employees`
--
ALTER TABLE `employees`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
