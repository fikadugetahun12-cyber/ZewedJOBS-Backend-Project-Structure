const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const aiController = require('../controllers/aiController');
const authMiddleware = require('../middleware/auth');
const validationMiddleware = require('../middleware/validation');
const rateLimitMiddleware = require('../middleware/rateLimit');

// Rate limiting for AI routes
router.use(rateLimitMiddleware.aiLimiter);

// Public AI endpoints (limited functionality)
router.post('/chat/public', [
  body('message').trim().notEmpty().isLength({ max: 1000 }),
  body('context').optional().isIn(['general', 'career', 'education'])
], validationMiddleware, aiController.publicChat);

// Protected routes (require authentication)
router.use(authMiddleware.protect);

// AI Chat Assistant
router.post('/chat', [
  body('message').trim().notEmpty().isLength({ max: 1000 }),
  body('context').optional().isIn(['job_search', 'career_advice', 'resume_review', 'interview_prep', 'course_guidance']),
  body('history').optional().isArray()
], validationMiddleware, aiController.chat);

router.get('/chat/history', aiController.getChatHistory);
router.delete('/chat/history/:id', aiController.deleteChatHistory);
router.delete('/chat/history', aiController.clearChatHistory);

// Resume AI Services
router.post('/resume/analyze', [
  body('resumeText').trim().notEmpty(),
  body('jobDescription').optional().trim()
], validationMiddleware, aiController.analyzeResume);

router.post('/resume/improve', [
  body('resumeText').trim().notEmpty(),
  body('targetJob').optional().trim(),
  body('improvementAreas').optional().isArray()
], validationMiddleware, aiController.improveResume);

router.post('/resume/generate', [
  body('personalInfo').isObject(),
  body('experience').isArray(),
  body('education').isArray(),
  body('skills').isArray(),
  body('template').optional().isIn(['modern', 'professional', 'creative', 'minimal'])
], validationMiddleware, aiController.generateResume);

// Cover Letter AI
router.post('/cover-letter/generate', [
  body('jobDetails').isObject(),
  body('resumeInfo').isObject(),
  body('tone').optional().isIn(['formal', 'semi-formal', 'enthusiastic'])
], validationMiddleware, aiController.generateCoverLetter);

// Job Search AI
router.post('/job/match', [
  body('resumeText').trim().notEmpty(),
  body('preferences').optional().isObject()
], validationMiddleware, aiController.matchJobs);

router.post('/job/recommendations', [
  body('skills').isArray(),
  body('experience').isInt({ min: 0 }),
  body('interests').optional().isArray(),
  body('location').optional().trim()
], validationMiddleware, aiController.getJobRecommendations);

// Interview AI
router.post('/interview/prepare', [
  body('jobDescription').trim().notEmpty(),
  body('companyInfo').optional().trim(),
  body('experienceLevel').optional().isIn(['entry', 'mid', 'senior'])
], validationMiddleware, aiController.prepareInterview);

router.post('/interview/practice', [
  body('question').trim().notEmpty(),
  body('answer').trim().notEmpty(),
  body('jobContext').optional().trim()
], validationMiddleware, aiController.practiceInterview);

// Career Path AI
router.post('/career/path', [
  body('currentSkills').isArray(),
  body('interests').isArray(),
  body('experience').isInt({ min: 0 }),
  body('goals').optional().isArray()
], validationMiddleware, aiController.suggestCareerPath);

router.post('/career/skills', [
  body('targetRole').trim().notEmpty(),
  body('currentSkills').isArray(),
  body('timeline').optional().isIn(['3months', '6months', '1year'])
], validationMiddleware, aiController.suggestSkills);

// Course Recommendation AI
router.post('/courses/recommend', [
  body('skills').isArray(),
  body('careerGoals').isArray(),
  body('learningStyle').optional().isIn(['visual', 'reading', 'hands-on']),
  body('timeCommitment').optional().isIn(['low', 'medium', 'high'])
], validationMiddleware, aiController.recommendCourses);

// Admin AI Management
router.use(authMiddleware.restrictTo('admin'));

router.get('/admin/usage', aiController.getAIUsageStats);
router.get('/admin/analytics', aiController.getAIAnalytics);
router.put('/admin/settings', [
  body('model').optional().isString(),
  body('maxTokens').optional().isInt({ min: 100, max: 4000 }),
  body('temperature').optional().isFloat({ min: 0, max: 1 }),
  body('rateLimit').optional().isInt({ min: 1 })
], validationMiddleware, aiController.updateAISettings);

// AI Model testing (admin only)
router.post('/admin/test', [
  body('prompt').trim().notEmpty(),
  body('model').optional().isString(),
  body('parameters').optional().isObject()
], validationMiddleware, aiController.testModel);

module.exports = router;
