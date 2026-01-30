const mongoose = require('mongoose');
const winston = require('winston');

// Create logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/database-error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/database-combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

class Database {
  constructor() {
    this._connect();
  }

  async _connect() {
    try {
      const mongoURI = process.env.NODE_ENV === 'production' 
        ? process.env.MONGODB_URI_PROD 
        : process.env.MONGODB_URI;

      if (!mongoURI) {
        throw new Error('MongoDB URI is not defined in environment variables');
      }

      mongoose.set('strictQuery', true);
      
      await mongoose.connect(mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });

      logger.info('✅ MongoDB connected successfully');
      
      // Handle connection events
      mongoose.connection.on('connected', () => {
        logger.info('Mongoose connected to DB');
      });

      mongoose.connection.on('error', (err) => {
        logger.error(`Mongoose connection error: ${err.message}`);
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('Mongoose disconnected from DB');
      });

      // Handle process termination
      process.on('SIGINT', async () => {
        await mongoose.connection.close();
        logger.info('Mongoose connection closed through app termination');
        process.exit(0);
      });

    } catch (error) {
      logger.error(`❌ MongoDB connection error: ${error.message}`);
      
      // Retry connection after 5 seconds
      setTimeout(() => {
        logger.info('Retrying MongoDB connection...');
        this._connect();
      }, 5000);
      
      throw error;
    }
  }

  // Health check
  async healthCheck() {
    try {
      await mongoose.connection.db.admin().ping();
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: 'MongoDB',
        connectionState: mongoose.connection.readyState
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Get connection status
  getStatus() {
    const states = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting'
    };
    return states[mongoose.connection.readyState] || 'unknown';
  }
}

// Create singleton instance
const database = new Database();

module.exports = database;
