const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  // Basic Information
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords do not match'
    }
  },
  firstName: {
    type: String,
    required: [true, 'Please provide your first name'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Please provide your last name'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  phone: {
    type: String,
    validate: {
      validator: function(v) {
        return /^(\+251|0)[79]\d{8}$/.test(v) || validator.isMobilePhone(v, 'any');
      },
      message: 'Please provide a valid phone number'
    }
  },

  // User Type & Role
  userType: {
    type: String,
    enum: ['job_seeker', 'employer', 'instructor', 'admin'],
    default: 'job_seeker'
  },
  role: {
    type: String,
    enum: ['user', 'moderator', 'admin'],
    default: 'user'
  },

  // Profile Information
  avatar: {
    type: String,
    default: 'default-avatar.png'
  },
  bio: {
    type: String,
    maxlength: [500, 'Bio cannot exceed 500 characters']
  },
  location: {
    city: String,
    country: String,
    timezone: String
  },
  dateOfBirth: Date,
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer_not_to_say']
  },

  // Job Seeker Specific
  jobSeekerProfile: {
    headline: String,
    currentPosition: String,
    currentCompany: String,
    yearsOfExperience: Number,
    education: [{
      institution: String,
      degree: String,
      field: String,
      graduationYear: Number,
      gpa: Number
    }],
    skills: [{
      name: String,
      level: {
        type: String,
        enum: ['beginner', 'intermediate', 'advanced', 'expert']
      },
      years: Number
    }],
    certifications: [{
      name: String,
      issuer: String,
      issueDate: Date,
      expiryDate: Date,
      credentialId: String
    }],
    languages: [{
      language: String,
      proficiency: {
        type: String,
        enum: ['basic', 'conversational', 'fluent', 'native']
      }
    }],
    resume: String,
    portfolio: String,
    desiredSalary: {
      min: Number,
      max: Number,
      currency: {
        type: String,
        default: 'ETB'
      }
    },
    jobPreferences: {
      jobTypes: [{
        type: String,
        enum: ['full-time', 'part-time', 'contract', 'internship', 'remote']
      }],
      locations: [String],
      industries: [String]
    }
  },

  // Employer Specific
  employerProfile: {
    companyName: {
      type: String,
      trim: true
    },
    companySize: {
      type: String,
      enum: ['1-10', '11-50', '51-200', '201-500', '500+']
    },
    industry: String,
    website: String,
    foundedYear: Number,
    description: String,
    logo: String,
    address: {
      street: String,
      city: String,
      state: String,
      country: String,
      postalCode: String
    },
    contactPerson: {
      name: String,
      position: String,
      phone: String
    },
    verified: {
      type: Boolean,
      default: false
    },
    subscription: {
      plan: {
        type: String,
        enum: ['free', 'basic', 'premium', 'enterprise'],
        default: 'free'
      },
      status: {
        type: String,
        enum: ['active', 'canceled', 'expired', 'pending'],
        default: 'pending'
      },
      expiresAt: Date,
      features: {
        jobPosts: Number,
        featuredJobs: Number,
        aiAssistance: Boolean,
        prioritySupport: Boolean
      }
    }
  },

  // Account Status & Security
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  
  isActive: {
    type: Boolean,
    default: true,
    select: false
  },
  deactivatedAt: Date,
  banned: {
    type: Boolean,
    default: false
  },
  banReason: String,
  banExpires: Date,

  // Activity Tracking
  lastLogin: Date,
  lastActive: Date,
  loginCount: {
    type: Number,
    default: 0
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockedUntil: Date,

  // Preferences
  preferences: {
    emailNotifications: {
      type: Boolean,
      default: true
    },
    pushNotifications: {
      type: Boolean,
      default: true
    },
    jobAlerts: {
      type: Boolean,
      default: true
    },
    newsletter: {
      type: Boolean,
      default: false
    },
    privacy: {
      profileVisibility: {
        type: String,
        enum: ['public', 'connections', 'private'],
        default: 'public'
      },
      showEmail: {
        type: Boolean,
        default: false
      },
      showPhone: {
        type: Boolean,
        default: false
      }
    }
  },

  // Social Connections
  connections: [{
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User'
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'blocked'],
      default: 'pending'
    },
    connectedAt: Date
  }],

  // Statistics
  statistics: {
    jobsApplied: {
      type: Number,
      default: 0
    },
    jobsPosted: {
      type: Number,
      default: 0
    },
    coursesEnrolled: {
      type: Number,
      default: 0
    },
    coursesCompleted: {
      type: Number,
      default: 0
    },
    totalSpent: {
      type: Number,
      default: 0
    },
    totalEarned: {
      type: Number,
      default: 0
    }
  },

  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ 'employerProfile.companyName': 1 });
userSchema.index({ userType: 1 });
userSchema.index({ 'location.city': 1, 'location.country': 1 });
userSchema.index({ createdAt: -1 });

// Virtual field for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual field for profile completion percentage
userSchema.virtual('profileCompletion').get(function() {
  let completion = 0;
  const fields = [
    'email', 'firstName', 'lastName', 'phone', 'avatar',
    this.userType === 'job_seeker' ? 'jobSeekerProfile.headline' : 'employerProfile.companyName'
  ];
  
  fields.forEach(field => {
    if (this.get(field)) completion += 20;
  });
  
  return Math.min(completion, 100);
});

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  // Only run if password was modified
  if (!this.isModified('password')) return next();

  // Hash password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);
  
  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

// Pre-save middleware for updating passwordChangedAt
userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();
  
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Pre-save middleware for updating timestamp
userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Query middleware to filter out inactive users
userSchema.pre(/^find/, function(next) {
  this.find({ isActive: { $ne: false } });
  next();
});

// Instance method to check password
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Instance method to check if password changed after token issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Instance method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Instance method to check if account is locked
userSchema.methods.isLocked = function() {
  return this.lockedUntil && this.lockedUntil > Date.now();
};

// Instance method to increment failed login attempts
userSchema.methods.incrementFailedLogin = async function() {
  this.failedLoginAttempts += 1;
  
  if (this.failedLoginAttempts >= 5) {
    this.lockedUntil = Date.now() + 30 * 60 * 1000; // 30 minutes
  }
  
  await this.save({ validateBeforeSave: false });
};

// Instance method to reset failed login attempts
userSchema.methods.resetFailedLogin = async function() {
  this.failedLoginAttempts = 0;
  this.lockedUntil = undefined;
  await this.save({ validateBeforeSave: false });
};

// Static method to find by email
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

// Static method to get user statistics
userSchema.statics.getUserStats = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: '$userType',
        count: { $sum: 1 },
        active: { 
          $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
        },
        verified: { 
          $sum: { $cond: [{ $eq: ['$isEmailVerified', true] }, 1, 0] }
        }
      }
    },
    {
      $project: {
        userType: '$_id',
        count: 1,
        active: 1,
        verified: 1,
        verificationRate: { 
          $multiply: [
            { $divide: ['$verified', '$count'] },
            100
          ]
        }
      }
    }
  ]);
  
  return stats;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
