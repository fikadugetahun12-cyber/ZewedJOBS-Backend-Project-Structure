const express = require('express');
const router = express.Router();
const { body, query, param } = require('express-validator');
const courseController = require('../controllers/courseController');
const authMiddleware = require('../middleware/auth');
const validationMiddleware = require('../middleware/validation');

// Public routes
router.get('/', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 }),
  query('search').optional().trim(),
  query('category').optional().trim(),
  query('level').optional().isIn(['beginner', 'intermediate', 'advanced']),
  query('priceMin').optional().isFloat({ min: 0 }),
  query('priceMax').optional().isFloat({ min: 0 }),
  query('duration').optional().isIn(['short', 'medium', 'long']),
  query('sort').optional().isIn(['newest', 'popular', 'rating', 'price_low', 'price_high']),
  query('instructor').optional().trim()
], validationMiddleware, courseController.getAllCourses);

router.get('/featured', courseController.getFeaturedCourses);
router.get('/categories', courseController.getCourseCategories);
router.get('/stats', courseController.getCourseStats);
router.get('/:id', [
  param('id').isMongoId()
], validationMiddleware, courseController.getCourse);

// Protected routes (require authentication)
router.use(authMiddleware.protect);

// Student routes
router.get('/user/enrolled', courseController.getEnrolledCourses);
router.get('/user/completed', courseController.getCompletedCourses);
router.get('/user/progress/:courseId', [
  param('courseId').isMongoId()
], validationMiddleware, courseController.getCourseProgress);

router.post('/:id/enroll', [
  param('id').isMongoId()
], validationMiddleware, courseController.enrollCourse);

router.post('/:id/complete', [
  param('id').isMongoId()
], validationMiddleware, courseController.markCourseComplete);

router.post('/:id/progress', [
  param('id').isMongoId(),
  body('progress').isFloat({ min: 0, max: 100 })
], validationMiddleware, courseController.updateProgress);

router.post('/:id/review', [
  param('id').isMongoId(),
  body('rating').isInt({ min: 1, max: 5 }),
  body('comment').optional().trim()
], validationMiddleware, courseController.addReview);

// Instructor/Admin routes
router.use(authMiddleware.restrictTo('instructor', 'admin'));

router.post('/', [
  body('title').trim().notEmpty().isLength({ max: 200 }),
  body('description').trim().notEmpty(),
  body('shortDescription').trim().notEmpty().isLength({ max: 500 }),
  body('category').trim().notEmpty(),
  body('level').isIn(['beginner', 'intermediate', 'advanced']),
  body('price').isFloat({ min: 0 }),
  body('duration').isInt({ min: 1 }),
  body('durationUnit').isIn(['hours', 'days', 'weeks']),
  body('prerequisites').optional().isArray(),
  body('learningOutcomes').isArray(),
  body('coverImage').optional().trim(),
  body('isFeatured').optional().isBoolean(),
  body('isPublished').optional().isBoolean()
], validationMiddleware, courseController.createCourse);

router.put('/:id', [
  param('id').isMongoId(),
  body('title').optional().trim().isLength({ max: 200 }),
  body('description').optional().trim(),
  body('shortDescription').optional().trim().isLength({ max: 500 }),
  body('category').optional().trim(),
  body('level').optional().isIn(['beginner', 'intermediate', 'advanced']),
  body('price').optional().isFloat({ min: 0 }),
  body('duration').optional().isInt({ min: 1 }),
  body('durationUnit').optional().isIn(['hours', 'days', 'weeks']),
  body('prerequisites').optional().isArray(),
  body('learningOutcomes').optional().isArray(),
  body('coverImage').optional().trim(),
  body('isFeatured').optional().isBoolean(),
  body('isPublished').optional().isBoolean()
], validationMiddleware, courseController.updateCourse);

router.delete('/:id', [
  param('id').isMongoId()
], validationMiddleware, courseController.deleteCourse);

// Course content management
router.post('/:id/sections', [
  param('id').isMongoId(),
  body('title').trim().notEmpty(),
  body('description').optional().trim(),
  body('order').isInt({ min: 0 })
], validationMiddleware, courseController.addSection);

router.put('/sections/:sectionId', [
  param('sectionId').isMongoId(),
  body('title').optional().trim(),
  body('description').optional().trim(),
  body('order').optional().isInt({ min: 0 })
], validationMiddleware, courseController.updateSection);

router.delete('/sections/:sectionId', [
  param('sectionId').isMongoId()
], validationMiddleware, courseController.deleteSection);

// Lesson management
router.post('/sections/:sectionId/lessons', [
  param('sectionId').isMongoId(),
  body('title').trim().notEmpty(),
  body('content').trim().notEmpty(),
  body('type').isIn(['video', 'article', 'quiz', 'assignment']),
  body('duration').optional().isInt({ min: 1 }),
  body('order').isInt({ min: 0 }),
  body('isFree').optional().isBoolean()
], validationMiddleware, courseController.addLesson);

router.put('/lessons/:lessonId', [
  param('lessonId').isMongoId(),
  body('title').optional().trim(),
  body('content').optional().trim(),
  body('type').optional().isIn(['video', 'article', 'quiz', 'assignment']),
  body('duration').optional().isInt({ min: 1 }),
  body('order').optional().isInt({ min: 0 }),
  body('isFree').optional().isBoolean()
], validationMiddleware, courseController.updateLesson);

router.delete('/lessons/:lessonId', [
  param('lessonId').isMongoId()
], validationMiddleware, courseController.deleteLesson);

// Instructor dashboard
router.get('/instructor/courses', courseController.getInstructorCourses);
router.get('/instructor/stats', courseController.getInstructorStats);
router.get('/:id/enrollments', [
  param('id').isMongoId()
], validationMiddleware, courseController.getCourseEnrollments);

// Admin routes
router.use(authMiddleware.restrictTo('admin'));

router.get('/admin/all', courseController.getAllCoursesAdmin);
router.put('/:id/approve', [
  param('id').isMongoId()
], validationMiddleware, courseController.approveCourse);
router.put('/:id/feature', [
  param('id').isMongoId()
], validationMiddleware, courseController.toggleFeatured);

module.exports = router;
