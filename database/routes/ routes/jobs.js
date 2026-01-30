const express = require('express');
const router = express.Router();
const { body, query } = require('express-validator');
const jobController = require('../controllers/jobController');
const authMiddleware = require('../middleware/auth');
const validationMiddleware = require('../middleware/validation');

// Public routes (no authentication required)
router.get('/', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('search').optional().trim(),
  query('location').optional().trim(),
  query('jobType').optional().isIn(['full-time', 'part-time', 'contract', 'internship', 'remote']),
  query('experience').optional().isIn(['entry', 'mid', 'senior', 'executive']),
  query('salaryMin').optional().isFloat({ min: 0 }),
  query('salaryMax').optional().isFloat({ min: 0 }),
  query('sort').optional().isIn(['newest', 'oldest', 'salary_high', 'salary_low']),
  query('company').optional().trim()
], validationMiddleware, jobController.getAllJobs);

router.get('/featured', jobController.getFeaturedJobs);
router.get('/stats', jobController.getJobStats);
router.get('/categories', jobController.getJobCategories);
router.get('/:id', jobController.getJob);

// Protected routes (require authentication)
router.use(authMiddleware.protect);

// Job seeker routes
router.post('/:id/apply', jobController.applyForJob);
router.get('/user/applications', jobController.getUserApplications);
router.get('/user/saved', jobController.getSavedJobs);
router.post('/:id/save', jobController.saveJob);
router.delete('/:id/unsave', jobController.unsaveJob);

// Employer routes
router.use(authMiddleware.restrictTo('employer', 'admin'));

router.post('/', [
  body('title').trim().notEmpty().isLength({ max: 200 }),
  body('description').trim().notEmpty(),
  body('requirements').isArray(),
  body('responsibilities').optional().isArray(),
  body('jobType').isIn(['full-time', 'part-time', 'contract', 'internship', 'remote']),
  body('location').trim().notEmpty(),
  body('salaryMin').isFloat({ min: 0 }),
  body('salaryMax').isFloat({ min: 0 }),
  body('experience').isIn(['entry', 'mid', 'senior', 'executive']),
  body('category').trim().notEmpty(),
  body('deadline').optional().isISO8601(),
  body('isFeatured').optional().isBoolean()
], validationMiddleware, jobController.createJob);

router.put('/:id', [
  body('title').optional().trim().isLength({ max: 200 }),
  body('description').optional().trim(),
  body('requirements').optional().isArray(),
  body('jobType').optional().isIn(['full-time', 'part-time', 'contract', 'internship', 'remote']),
  body('location').optional().trim(),
  body('salaryMin').optional().isFloat({ min: 0 }),
  body('salaryMax').optional().isFloat({ min: 0 }),
  body('experience').optional().isIn(['entry', 'mid', 'senior', 'executive']),
  body('category').optional().trim(),
  body('deadline').optional().isISO8601(),
  body('isActive').optional().isBoolean(),
  body('isFeatured').optional().isBoolean()
], validationMiddleware, jobController.updateJob);

router.delete('/:id', jobController.deleteJob);
router.get('/employer/jobs', jobController.getEmployerJobs);
router.get('/:id/applications', jobController.getJobApplications);
router.put('/applications/:applicationId/status', [
  body('status').isIn(['pending', 'reviewing', 'shortlisted', 'rejected', 'accepted'])
], validationMiddleware, jobController.updateApplicationStatus);

// Admin routes
router.use(authMiddleware.restrictTo('admin'));

router.get('/admin/all', jobController.getAllJobsAdmin);
router.put('/:id/feature', jobController.toggleFeatured);
router.put('/:id/approve', jobController.approveJob);
router.put('/:id/reject', jobController.rejectJob);

module.exports = router;
