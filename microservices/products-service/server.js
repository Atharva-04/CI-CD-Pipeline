const express = require('express');
const { Pool } = require('pg');
const redis = require('redis');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const promClient = require('prom-client');
const winston = require('winston');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure logging
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'products-service.log' })
  ]
});

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Redis connection for caching
const redisClient = redis.createClient({
  url: process.env.REDIS_URL
});

redisClient.on('error', (err) => logger.error('Redis Client Error', err));
redisClient.connect();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// Initialize database tables
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        category VARCHAR(100),
        stock INTEGER DEFAULT 0,
        image_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert sample data if table is empty
    const { rowCount } = await pool.query('SELECT COUNT(*) FROM products');
    if (rowCount === 0) {
      await pool.query(`
        INSERT INTO products (name, description, price, category, stock, image_url) VALUES
        ('Laptop', 'High-performance laptop', 999.99, 'electronics', 50, 'laptop.jpg'),
        ('Smartphone', 'Latest smartphone model', 699.99, 'electronics', 100, 'phone.jpg'),
        ('Headphones', 'Wireless noise-cancelling headphones', 199.99, 'electronics', 75, 'headphones.jpg'),
        ('Book', 'Programming guide', 49.99, 'books', 200, 'book.jpg'),
        ('Coffee Mug', 'Ceramic coffee mug', 12.99, 'home', 150, 'mug.jpg')
      `);
      logger.info('Sample products inserted');
    }
  } catch (error) {
    logger.error('Database initialization error:', error);
  }
}

initDatabase();

// Health check
app.get('/health', async (req, res) => {
  try {
    // Check database connection
    await pool.query('SELECT 1');
    
    // Check Redis connection
    await redisClient.ping();

    res.json({
      status: 'healthy',
      service: 'products-service',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      dependencies: {
        database: 'healthy',
        cache: 'healthy'
      }
    });
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const { category, page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;
    
    // Try to get from cache first
    const cacheKey = `products:${category || 'all'}:${page}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    
    if (cached) {
      return res.json(JSON.parse(cached));
    }

    let query = 'SELECT * FROM products';
    let params = [];
    
    if (category) {
      query += ' WHERE category = $1';
      params.push(category);
      query += ` LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
      params.push(limit, offset);
    } else {
      query += ' LIMIT $1 OFFSET $2';
      params.push(limit, offset);
    }

    const result = await pool.query(query, params);
    
    // Cache the result
    await redisClient.setEx(cacheKey, 300, JSON.stringify(result.rows)); // 5 minutes cache

    res.json(result.rows);
  } catch (error) {
    logger.error('Get products error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const cacheKey = `product:${id}`;
    const cached = await redisClient.get(cacheKey);
    
    if (cached) {
      return res.json(JSON.parse(cached));
    }

    const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const product = result.rows[0];
    await redisClient.setEx(cacheKey, 600, JSON.stringify(product)); // 10 minutes cache

    res.json(product);
  } catch (error) {
    logger.error('Get product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new product (protected route)
app.post('/api/products', [
  body('name').notEmpty().withMessage('Name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('category').notEmpty().withMessage('Category is required')
], async (req, res) => {
  try {
    // Verify JWT token with auth service
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token with auth service
    const authResponse = await axios.post(
      `${process.env.AUTH_SERVICE_URL}/api/verify`,
      {},
      { headers: { authorization: `Bearer ${token}` } }
    );

    if (!authResponse.data.valid || authResponse.data.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price, category, stock, image_url } = req.body;

    const result = await pool.query(
      `INSERT INTO products (name, description, price, category, stock, image_url) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name, description, price, category, stock || 0, image_url]
    );

    // Clear cache
    await redisClient.del('products:*');

    logger.info(`Product created: ${name} by user ${authResponse.data.user.username}`);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    logger.error('Create product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update product stock
app.patch('/api/products/:id/stock', async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity, operation } = req.body; // operation: 'add' or 'subtract'

    const result = await pool.query(
      `UPDATE products SET stock = stock ${operation === 'subtract' ? '-' : '+'} $1 
       WHERE id = $2 RETURNING *`,
      [quantity, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Clear cache
    await redisClient.del(`product:${id}`);
    await redisClient.del('products:*');

    res.json(result.rows[0]);

  } catch (error) {
    logger.error('Update stock error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', promClient.register.contentType);
  res.end(await promClient.register.metrics());
});

app.listen(PORT, () => {
  logger.info(`Products Service running on port ${PORT}`);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  pool.end(() => {
    redisClient.quit(() => {
      process.exit(0);
    });
  });
});
