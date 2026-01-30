const express = require('express');
const router = express.Router();
const { body, param } = require('express-validator');
const paymentController = require('../controllers/paymentController');
const authMiddleware = require('../middleware/auth');
const validationMiddleware = require('../middleware/validation');

// Webhook endpoints (no authentication required)
router.post('/webhook/stripe', express.raw({ type: 'application/json' }), paymentController.stripeWebhook);
router.post('/webhook/telebirr', express.raw({ type: 'application/json' }), paymentController.telebirrWebhook);
router.post('/webhook/cbe', express.raw({ type: 'application/json' }), paymentController.cbeWebhook);

// Protected routes (require authentication)
router.use(authMiddleware.protect);

// Payment initialization
router.post('/initialize', [
  body('amount').isFloat({ min: 1 }),
  body('currency').isIn(['ETB', 'USD']),
  body('paymentMethod').isIn(['stripe', 'telebirr', 'cbe', 'paypal']),
  body('serviceType').isIn(['job_application', 'course_enrollment', 'job_posting', 'premium_subscription']),
  body('serviceId').notEmpty(),
  body('metadata').optional().isObject()
], validationMiddleware, paymentController.initializePayment);

// Payment verification
router.post('/verify/:paymentId', [
  param('paymentId').isMongoId()
], validationMiddleware, paymentController.verifyPayment);

// User payment history
router.get('/history', paymentController.getPaymentHistory);
router.get('/history/:id', [
  param('id').isMongoId()
], validationMiddleware, paymentController.getPaymentDetails);

// Refund requests
router.post('/refund/:paymentId', [
  param('paymentId').isMongoId(),
  body('reason').trim().notEmpty()
], validationMiddleware, paymentController.requestRefund);

// Subscription management
router.get('/subscriptions', paymentController.getUserSubscriptions);
router.post('/subscriptions', [
  body('planId').notEmpty(),
  body('paymentMethod').isIn(['stripe', 'telebirr', 'cbe'])
], validationMiddleware, paymentController.createSubscription);
router.put('/subscriptions/:id/cancel', [
  param('id').isMongoId()
], validationMiddleware, paymentController.cancelSubscription);

// Invoice management
router.get('/invoices', paymentController.getInvoices);
router.get('/invoices/:id/download', [
  param('id').isMongoId()
], validationMiddleware, paymentController.downloadInvoice);

// Payment methods management
router.get('/payment-methods', paymentController.getPaymentMethods);
router.post('/payment-methods', [
  body('type').isIn(['card', 'telebirr', 'cbe_account']),
  body('details').isObject()
], validationMiddleware, paymentController.addPaymentMethod);
router.delete('/payment-methods/:id', [
  param('id').isMongoId()
], validationMiddleware, paymentController.removePaymentMethod);

// Employer/admin routes
router.use(authMiddleware.restrictTo('employer', 'admin'));

router.get('/employer/transactions', paymentController.getEmployerTransactions);
router.post('/employer/deposit', [
  body('amount').isFloat({ min: 100 }),
  body('paymentMethod').isIn(['telebirr', 'cbe', 'bank_transfer'])
], validationMiddleware, paymentController.employerDeposit);

// Admin only routes
router.use(authMiddleware.restrictTo('admin'));

router.get('/admin/all', paymentController.getAllPayments);
router.get('/admin/stats', paymentController.getPaymentStats);
router.get('/admin/revenue', paymentController.getRevenueReport);
router.put('/refunds/:id/process', [
  param('id').isMongoId(),
  body('status').isIn(['approved', 'rejected']),
  body('adminNotes').optional().trim()
], validationMiddleware, paymentController.processRefund);

// Payment gateway status
router.get('/gateway-status', paymentController.getGatewayStatus);

module.exports = router;
