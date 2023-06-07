-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jun 07, 2023 at 04:32 AM
-- Server version: 10.4.24-MariaDB
-- PHP Version: 7.4.29

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `web_mata_bunda`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email` varchar(100) NOT NULL,
  `name` varchar(100) NOT NULL,
  `password` varchar(256) NOT NULL,
  `token` text DEFAULT NULL,
  `status_validasi` text DEFAULT NULL,
  `level` varchar(256) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `update_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `email`, `name`, `password`, `token`, `status_validasi`, `level`, `created_at`, `update_at`) VALUES
(3, 'mohfiqiherinsyah@gmail.com', 'Moh. Fiqih Erinsyah', 'pbkdf2:sha256:600000$BHVN6bAxNnddNalU$333a7226be8235449500a393f2781c3105f0c90de4a64b8df9acd16c4f43d36a', 'bW9oZmlxaWhlcmluc3lhaEBnbWFpbC5jb20=', 'Valid', 'Administrator', '2023-04-25 03:56:20', '2023-06-05 12:23:48'),
(9, 'mfiqiherinsyah90@gmail.com', 'mfiqiherinsyah90', 'pbkdf2:sha256:600000$sBgQVDT0nqhHg8Jz$b1a3a0f0a7c67835edb00b0371a3737299927085cb2000c534d7f7a1084e7c62', 'bWZpcWloZXJpbnN5YWg5MEBnbWFpbC5jb20=bWZpcWloZXJpbnN5YWg5MEBnbWFpbC5jb20=', 'Valid', 'User', '2023-05-08 08:31:51', '2023-06-04 09:39:18'),
(25, 'jupe@gmail.com', 'jupee', 'pbkdf2:sha256:600000$7T2FvihdxORCfhMz$0e0af8daf35800eb0209d715cdca801c3395f6953c6d8897b93b3cd534fb4444', NULL, 'Belum Validasi', 'User', '2023-06-05 12:37:53', '2023-06-05 12:37:53');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=26;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
