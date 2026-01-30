const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/auth');
const rateLimitMiddleware = require('../middleware/rateLimit');
const validationMiddleware = require('../middleware/validation');

// Rate limiting for auth routes
router.use(rateLimitMiddleware.authLimiter);

// Validation rules
const registerValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$/),
  body('firstName').trim().notEmpty(),
  body('lastName').trim().notEmpty(),
  body('phone').optional().isMobilePhone(),
  body('userType').isIn(['job_seeker', 'employer', 'admin'])
];

const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
];

const resetPasswordValidation = [
  body('email').isEmail().normalizeEmail()
];

const updatePasswordValidation = [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$/)
];

// Public routes
router.post('/register', registerValidation, validationMiddleware, authController.register);
router.post('/login', loginValidation, validationMiddleware, authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/forgot-password', resetPasswordValidation, validationMiddleware, authController.forgotPassword);
router.post('/reset-password/:token', updatePasswordValidation, validationMiddleware, authController.resetPassword);
router.post('/verify-email/:token', authController.verifyEmail);
router.post('/resend-verification', authController.resendVerification);

// Protected routes (require authentication)
router.use(authMiddleware.protect);

router.get('/me', authController.getMe);
router.put('/update-profile', authController.updateProfile);
router.put('/update-password', updatePasswordValidation, validationMiddleware, authController.updatePassword);
router.post('/upload-profile-picture', authController.uploadProfilePicture);
router.delete('/delete-account', authController.deleteAccount);

// Admin only routes
router.use(authMiddleware.restrictTo('admin'));

router.get('/users', authController.getAllUsers);
router.get('/users/:id', authController.getUser);
router.put('/users/:id', authController.updateUser);
router.delete('/users/:id', authController.deleteUser);
router.put('/users/:id/ban', authController.banUser);
router.put('/users/:id/unban', authController.unbanUser);

// Employer routes
router.use(authMiddleware.restrictTo('employer', 'admin'));
router.get('/employer/stats', authController.getEmployerStats);

module.exports = router;
