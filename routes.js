const express = require('express');
const router = express.Router();
const controllers = require('./controllers');
const { protect, adminProtect, frontDeskProtect } = require('./authMiddleware');

// --- User & Auth Routes ---
router.post('/register', controllers.registerUser);
router.post('/login', controllers.loginUser);
router.get('/users/profile', protect, controllers.getUserProfile);
router.post('/forgot-password', controllers.forgotPassword);
router.post('/reset-password', controllers.resetPassword);

// --- Store & Services Routes ---
router.get('/store-info', controllers.getStoreInfo);
router.get('/services', controllers.getAllServices);
router.post('/services', protect, adminProtect, controllers.createService);
router.put('/services/:id', protect, adminProtect, controllers.updateService);
router.delete('/services/:id', protect, adminProtect, controllers.deleteService);

// --- Therapists Route ---
router.get('/therapists', protect, controllers.getAllTherapists);

// --- Schedule Routes ---
router.get('/schedules/:employeeId', protect, controllers.getEmployeeSchedule);
router.post('/schedules', protect, controllers.updateEmployeeSchedule);

// --- Reservation Routes ---
router.post('/reservations', protect, controllers.createReservation);
router.get('/reservations/myreservations', protect, controllers.getCustomerReservations);
router.get('/reservations/employee', protect, controllers.getEmployeeReservations);
router.get('/reservations/therapist/:therapistId', protect, controllers.getTherapistReservationsByDate);
router.patch('/reservations/:id/cancel', protect, controllers.cancelReservation);

// --- Routes for Front Desk, Admins, and Employers ---
router.get('/reservations/all', protect, frontDeskProtect, controllers.getAllReservations);
router.post('/reservations/custom', protect, frontDeskProtect, controllers.createCustomReservation);

// --- Routes for Admins and Employers Only ---
router.get('/users/all', protect, adminProtect, controllers.getAllUsers);
router.post('/users', protect, adminProtect, controllers.createUser);
router.put('/users/:id', protect, adminProtect, controllers.updateUser);
router.delete('/users/:id', protect, adminProtect, controllers.deleteUser);
router.get('/employees/:internalUserId/services', protect, controllers.getEmployeeServices);
router.put('/employees/:internalUserId/services', protect, controllers.updateEmployeeServices);

module.exports = router;

