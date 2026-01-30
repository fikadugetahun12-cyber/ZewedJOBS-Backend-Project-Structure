const jwt = require('jsonwebtoken');
const User = require('../database/models/User');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Protect routes - require authentication
exports.protect = catchAsync(async (req, res, next) => {
  let token;
  
  // Get token from Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  // Get token from cookie
  else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  // Check if token exists
  if (!token) {
    return next(new AppError('You are not logged in. Please log in to access.', 401));
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    // Check if user changed password after token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('User recently changed password. Please log in again.', 401));
    }

    // Check if user is active
    if (!currentUser.isActive) {
      return next(new AppError('Your account has been deactivated.', 403));
    }

    // Grant access to protected route
    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid token. Please log in again.', 401));
    }
    if (err.name === 'TokenExpiredError') {
      return next(new AppError('Your token has expired. Please log in again.', 401));
    }
    return next(err);
  }
});

// Restrict to certain user roles
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.userType)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }
    next();
  };
};

// Check if user is logged in (for views)
exports.isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      const decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET);

      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next();
      }

      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next();
      }

      res.locals.user = currentUser;
      return next();
    } catch (err) {
      return next();
    }
  }
  next();
};

// Check if user owns resource
exports.checkOwnership = (model, paramName = 'id') => {
  return catchAsync(async (req, res, next) => {
    const resource = await model.findById(req.params[paramName]);
    
    if (!resource) {
      return next(new AppError('Resource not found', 404));
    }

    // Check if user is admin or owner
    if (req.user.userType !== 'admin' && resource.user.toString() !== req.user.id.toString()) {
      return next(new AppError('You do not own this resource', 403));
    }

    req.resource = resource;
    next();
  });
};

// Check if user has applied for job
exports.checkJobApplication = catchAsync(async (req, res, next) => {
  const jobId = req.params.id;
  const userId = req.user.id;

  const application = await Application.findOne({
    job: jobId,
    applicant: userId
  });

  if (application) {
    return next(new AppError('You have already applied for this job', 400));
  }

  next();
});

// Check subscription status for employers
exports.checkSubscription = catchAsync(async (req, res, next) => {
  if (req.user.userType !== 'employer') {
    return next();
  }

  const employer = await Employer.findById(req.user.id).populate('subscription');

  if (!employer.subscription || employer.subscription.status !== 'active') {
    return next(new AppError('You need an active subscription to perform this action', 402));
  }

  // Check if subscription has expired
  if (employer.subscription.expiresAt < Date.now()) {
    return next(new AppError('Your subscription has expired', 402));
  }

  next();
});

// Rate limiting based on user plan
exports.rateLimitByPlan = (req, res, next) => {
  const user = req.user;
  const plan = user.subscription?.plan || 'free';

  const limits = {
    free: { requests: 100, window: 15 * 60 * 1000 }, // 15 minutes
    basic: { requests: 500, window: 15 * 60 * 1000 },
    premium: { requests: 2000, window: 15 * 60 * 1000 },
    enterprise: { requests: 10000, window: 15 * 60 * 1000 }
  };

  const limit = limits[plan];
  
  // Implement rate limiting logic here
  // You can use a Redis store for distributed rate limiting
  
  next();
};

// CSRF protection
exports.csrfProtection = (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  
  if (!csrfToken || csrfToken !== req.session.csrfToken) {
    return next(new AppError('Invalid CSRF token', 403));
  }

  next();
};
