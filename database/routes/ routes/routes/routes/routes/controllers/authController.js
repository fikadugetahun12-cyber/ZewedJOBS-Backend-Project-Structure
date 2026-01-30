const User = require('../database/models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const sendEmail = require('../utils/emailService');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Generate JWT Token
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

// Create and send token
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  
  // Remove password from output
  user.password = undefined;

  // Cookie options
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);

  res.status(statusCode).json({
    status: 'success',
    token,
    data: { user }
  });
};

// Register new user
exports.register = catchAsync(async (req, res, next) => {
  const { email, password, firstName, lastName, phone, userType } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User already exists with this email', 400));
  }

  // Create verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const hashedVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');

  // Create new user
  const user = await User.create({
    email,
    password,
    firstName,
    lastName,
    phone,
    userType,
    emailVerificationToken: hashedVerificationToken,
    emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
  });

  // Send verification email
  const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verificationToken}`;
  
  try {
    await sendEmail({
      email: user.email,
      subject: 'Verify your email address',
      template: 'emailVerification',
      data: {
        name: user.firstName,
        verificationUrl,
        expiryHours: 24
      }
    });
  } catch (err) {
    // Don't fail registration if email fails
    console.error('Failed to send verification email:', err);
  }

  createSendToken(user, 201, res);
});

// Login user
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }

  // Check if user exists and password is correct
  const user = await User.findOne({ email }).select('+password +isActive');
  
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // Check if user is active
  if (!user.isActive) {
    return next(new AppError('Your account has been deactivated. Please contact support.', 403));
  }

  // Check if email is verified
  if (!user.isEmailVerified) {
    return next(new AppError('Please verify your email address first', 401));
  }

  // Update last login
  user.lastLogin = Date.now();
  await user.save({ validateBeforeSave: false });

  createSendToken(user, 200, res);
});

// Get current user
exports.getMe = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id)
    .select('-__v -passwordChangedAt')
    .populate('profile');

  res.status(200).json({
    status: 'success',
    data: { user }
  });
});

// Update user profile
exports.updateProfile = catchAsync(async (req, res, next) => {
  // Filter out fields that shouldn't be updated
  const filteredBody = {};
  const allowedFields = [
    'firstName', 'lastName', 'phone', 'bio', 'avatar', 
    'location', 'website', 'linkedin', 'github', 'twitter'
  ];
  
  allowedFields.forEach(field => {
    if (req.body[field] !== undefined) {
      filteredBody[field] = req.body[field];
    }
  });

  const user = await User.findByIdAndUpdate(
    req.user.id,
    filteredBody,
    {
      new: true,
      runValidators: true
    }
  ).select('-__v -password -passwordChangedAt');

  res.status(200).json({
    status: 'success',
    data: { user }
  });
});

// Update password
exports.updatePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  // Get user with password
  const user = await User.findById(req.user.id).select('+password');

  // Check if current password is correct
  if (!(await user.correctPassword(currentPassword, user.password))) {
    return next(new AppError('Your current password is wrong', 401));
  }

  // Update password
  user.password = newPassword;
  user.passwordChangedAt = Date.now() - 1000;
  await user.save();

  createSendToken(user, 200, res);
});

// Forgot password
exports.forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  // Get user by email
  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError('There is no user with that email address', 404));
  }

  // Generate reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // Send email with reset token
  const resetURL = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Reset your password (valid for 10 minutes)',
      template: 'passwordReset',
      data: {
        name: user.firstName,
        resetURL,
        expiryMinutes: 10
      }
    });

    res.status(200).json({
      status: 'success',
      message: 'Password reset token sent to email'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email. Try again later.', 500));
  }
});

// Reset password
exports.resetPassword = catchAsync(async (req, res, next) => {
  // Hash the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  // Find user by token and check expiration
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  // Set new password
  user.password = req.body.newPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  user.passwordChangedAt = Date.now() - 1000;
  await user.save();

  // Log the user in
  createSendToken(user, 200, res);
});

// Verify email
exports.verifyEmail = catchAsync(async (req, res, next) => {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: Date.now() }
  });

  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  // Update user verification status
  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;
  await user.save();

  res.status(200).json({
    status: 'success',
    message: 'Email verified successfully'
  });
});

// Resend verification email
exports.resendVerification = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  if (user.isEmailVerified) {
    return next(new AppError('Email is already verified', 400));
  }

  // Create new verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const hashedVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');

  user.emailVerificationToken = hashedVerificationToken;
  user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
  await user.save({ validateBeforeSave: false });

  // Send verification email
  const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verificationToken}`;

  await sendEmail({
    email: user.email,
    subject: 'Verify your email address',
    template: 'emailVerification',
    data: {
      name: user.firstName,
      verificationUrl,
      expiryHours: 24
    }
  });

  res.status(200).json({
    status: 'success',
    message: 'Verification email sent'
  });
});

// Refresh token
exports.refreshToken = catchAsync(async (req, res, next) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return next(new AppError('Refresh token is required', 400));
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return next(new AppError('User no longer exists', 401));
    }

    // Generate new access token
    const accessToken = signToken(user._id);

    res.status(200).json({
      status: 'success',
      accessToken
    });
  } catch (err) {
    return next(new AppError('Invalid refresh token', 401));
  }
});

// Upload profile picture
exports.uploadProfilePicture = catchAsync(async (req, res, next) => {
  if (!req.file) {
    return next(new AppError('Please upload an image file', 400));
  }

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { avatar: req.file.path },
    { new: true, runValidators: true }
  ).select('-__v -password -passwordChangedAt');

  res.status(200).json({
    status: 'success',
    data: { user }
  });
});

// Get all users (admin only)
exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find()
    .select('-__v -password -passwordChangedAt')
    .sort('-createdAt');

  res.status(200).json({
    status: 'success',
    results: users.length,
    data: { users }
  });
});

// Delete account
exports.deleteAccount = catchAsync(async (req, res, next) => {
  const { password } = req.body;

  if (!password) {
    return next(new AppError('Please provide your password', 400));
  }

  const user = await User.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect password', 401));
  }

  // Soft delete (mark as inactive)
  user.isActive = false;
  user.deactivatedAt = Date.now();
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'Your account has been deactivated'
  });
});

// Get employer stats
exports.getEmployerStats = catchAsync(async (req, res, next) => {
  const stats = await User.aggregate([
    {
      $match: { userType: 'employer', isActive: true }
    },
    {
      $lookup: {
        from: 'jobs',
        localField: '_id',
        foreignField: 'employer',
        as: 'jobs'
      }
    },
    {
      $project: {
        _id: 1,
        companyName: 1,
        email: 1,
        totalJobs: { $size: '$jobs' },
        activeJobs: {
          $size: {
            $filter: {
              input: '$jobs',
              as: 'job',
              cond: { $eq: ['$$job.isActive', true] }
            }
          }
        },
        createdAt: 1
      }
    },
    {
      $sort: { totalJobs: -1 }
    }
  ]);

  res.status(200).json({
    status: 'success',
    data: { stats }
  });
});
