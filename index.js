/******************************************************************************
 *  index.js  –  Secure API Fitness • Express + SQLite
 *  Production-ready security without password complexity requirements
 *  Full JWT authentication and authorization
 *  Code: GuestAUser - Github
 *******************************************************************************/

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const path = require('path');
const Joi = require('joi');
const winston = require('winston');
const DOMPurify = require('isomorphic-dompurify');
const { body, param, query, validationResult } = require('express-validator');
const crypto = require('crypto');
const { db } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change-this-in-production';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'dev-refresh-secret-change-this-in-production';

if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.warn('⚠️  WARNING: Using default JWT secrets. Set JWT_SECRET and REFRESH_TOKEN_SECRET in production!');
}

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_EXPIRES_IN = '7d';

const fs = require('fs');
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

/* ---------- Enhanced Logging ---------- */
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'fitness-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.File({ filename: 'logs/security.log', level: 'warn' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'HH:mm:ss' }),
      winston.format.printf(({ level, message, timestamp }) =>
        `[${timestamp}] ${level}: ${message}`
      )
    )
  }));
}

const logSecurityEvent = (event, req, details = {}) => {
  const eventData = {
    event,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    url: req.originalUrl,
    method: req.method,
    userId: req.user?.id || null,
    timestamp: new Date().toISOString(),
    ...details
  };

  logger.warn('SECURITY_EVENT', eventData);

  if (['INVALID_TOKEN', 'ACCOUNT_LOCKED', 'RATE_LIMIT_EXCEEDED', 'UNAUTHORIZED_ACCESS_ATTEMPT'].includes(event)) {
    db.run(
      'INSERT INTO security_events (event_type, user_id, ip_address, details, severity) VALUES (?, ?, ?, ?, ?)',
      [event, req.user?.id || null, req.ip, JSON.stringify(details), 'high'],
      (err) => {
        if (err) logger.error('Failed to log security event to database:', err);
      }
    );
  }
};

/* ---------- Advanced Rate Limiting ---------- */
const createRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: { success: false, message },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    handler: (req, res) => {
      logSecurityEvent('RATE_LIMIT_EXCEEDED', req, { limit: max, window: windowMs });
      res.status(429).json({ success: false, message });
    }
  });
};

// Strict rate limits;
const generalLimiter = createRateLimiter(5 * 60 * 1000, 100, 'Muitas requisições. Tente novamente em 5 minutos.');
const authLimiter = createRateLimiter(5 * 60 * 1000, 5, 'Muitas tentativas de login. Tente novamente em 5 minutos.');
const createAccountLimiter = createRateLimiter(60 * 60 * 1000, 3, 'Limite de criação de contas excedido. Tente novamente em 1 hora.');
const strictLimiter = createRateLimiter(60 * 1000, 20, 'Limite de requisições excedido. Aguarde 1 minuto.');

// Progressive slow down;
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 30,
  delayMs: () => 500,
  maxDelayMs: 20000
});

/* ---------- Security Headers ---------- */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      imgSrc: ["'self'", "data:", "https://*.tile.openstreetmap.org"],
      connectSrc: ["'self'", "https://nominatim.openstreetmap.org", "https://overpass-api.de", "https://viacep.com.br"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 63072000, // 2 years;
    includeSubDomains: true,
    preload: true
  }
}));

/* ---------- CORS Configuration ---------- */
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://127.0.0.1:3000'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, Postman, or same-origin);
    if (!origin) return callback(null, true);
    
    // In development, allow all localhost origins; (Future reference).
    if (process.env.NODE_ENV !== 'production' && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logSecurityEvent('CORS_VIOLATION', { headers: { origin } }, { origin });
      callback(new Error('Não permitido pelo CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-Request-Id'],
  maxAge: 86400 // 24 hours;
}));

/* ---------- Request ID Middleware ---------- */
app.use((req, res, next) => {
  req.id = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-Id', req.id);
  next();
});

/* ---------- Body Parsing ---------- */
app.use(express.json({ 
  limit: '100kb', // Strict limit for limited server resources.
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      logSecurityEvent('MALFORMED_JSON', req, { error: e.message });
      throw new Error('JSON inválido');
    }
  }
}));

app.use(express.urlencoded({ extended: false, limit: '100kb' }));

app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  setHeaders: (res) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'SAMEORIGIN'); // Changed from DENY to allow the app;
  }
}));

/* ---------- Request Logging ---------- */
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', {
    stream: { write: message => logger.info(message.trim()) }
  }));
}

/* ---------- Input Sanitization ---------- */
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    // Remove any HTML tags and trim whitespace;
    return DOMPurify.sanitize(input, { ALLOWED_TAGS: [] }).trim();
  }
  return input;
};

const sanitizeBody = (req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    Object.keys(req.body).forEach(key => {
      req.body[key] = sanitizeInput(req.body[key]);
    });
  }
  next();
};

/* ---------- Validation Schemas ---------- */
const schemas = {
  cadastro: Joi.object({
    nome: Joi.string().min(2).max(100).trim().required()
      .pattern(/^[a-zA-ZÀ-ÿ\s'-]+$/).message('Nome deve conter apenas letras, espaços, hífens e apóstrofos'),
    cpf: Joi.string().length(11).pattern(/^\d+$/).required(),
    email: Joi.string().email().max(255).lowercase().trim().required(),
    senha: Joi.string().min(6).max(72).required() // Simple password requirement because of demo enviroment
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    senha: Joi.string().required()
  }),

  cep: Joi.string().length(8).pattern(/^\d+$/),

  parques: Joi.object({
    cep: Joi.string().length(8).pattern(/^\d+$/).required(),
    raio: Joi.number().min(500).max(10000).default(3000)
  })
};

/* ---------- JWT Authentication Middleware ---------- */
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Token de autenticação requerido',
        code: 'NO_TOKEN'
      });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          logSecurityEvent('EXPIRED_TOKEN', req);
          return res.status(401).json({ 
            success: false, 
            message: 'Token expirado',
            code: 'TOKEN_EXPIRED'
          });
        }
        
        logSecurityEvent('INVALID_TOKEN', req, { error: err.message });
        return res.status(401).json({ 
          success: false, 
          message: 'Token inválido',
          code: 'INVALID_TOKEN'
        });
      }

      db.get(
        'SELECT id, nome, email FROM usuarios WHERE id = ?',
        [decoded.id],
        (dbErr, user) => {
          if (dbErr) {
            logger.error('Database error during authentication:', dbErr);
            return res.status(500).json({ success: false, message: 'Erro interno' });
          }

          if (!user) {
            logSecurityEvent('TOKEN_USER_NOT_FOUND', req, { tokenUserId: decoded.id });
            return res.status(401).json({ 
              success: false, 
              message: 'Usuário não encontrado',
              code: 'USER_NOT_FOUND'
            });
          }

          req.user = {
            id: user.id,
            nome: user.nome,
            email: user.email
          };

          next();
        }
      );
    });
  } catch (error) {
    logger.error('Authentication middleware error:', error);
    res.status(500).json({ success: false, message: 'Erro de autenticação' });
  }
};

/* ---------- Error Handling ---------- */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logSecurityEvent('VALIDATION_ERROR', req, { errors: errors.array() });
    return res.status(400).json({
      success: false,
      message: 'Dados inválidos',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  next();
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/* ---------- Database Migrations ---------- */ /* SENSITIVE STRUCTURE */
const runMigrations = () => {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        cpf TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        senha TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (!err) {
        const newColumns = [
          'ALTER TABLE usuarios ADD COLUMN failed_login_attempts INTEGER DEFAULT 0',
          'ALTER TABLE usuarios ADD COLUMN locked_until DATETIME',
          'ALTER TABLE usuarios ADD COLUMN last_login DATETIME',
          'ALTER TABLE usuarios ADD COLUMN is_active BOOLEAN DEFAULT 1',
          'ALTER TABLE usuarios ADD COLUMN password_changed_at DATETIME',
          'ALTER TABLE usuarios ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP'
        ];

        newColumns.forEach(query => {
          db.run(query, (err) => {
            // Ignore errors - column might already exist;
            if (err && !err.message.includes('duplicate column')) {
              logger.debug('Column migration:', err.message);
            }
          });
        });
      }
    });

    // CEP history.
    db.run(`
      CREATE TABLE IF NOT EXISTS user_ceps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        cep TEXT NOT NULL,
        search_count INTEGER DEFAULT 1,
        last_searched DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        UNIQUE(user_id, cep)
      )
    `);

    // Refresh tokens.
    db.run(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
      )
    `);

    // Active sessions.
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        ip_address TEXT,
        user_agent TEXT,
        expires_at DATETIME NOT NULL,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
      )
    `);

    // Audit logs.
    db.run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        request_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE SET NULL
      )
    `);

    // Security events.
    db.run(`
      CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT,
        details TEXT,
        severity TEXT DEFAULT 'medium',
        resolved BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Indexes <-> performance.
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)',
      'CREATE INDEX IF NOT EXISTS idx_user_ceps_user_id ON user_ceps(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_user_ceps_last_searched ON user_ceps(last_searched DESC)',
      'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at DESC)'
    ];

    indexes.forEach(index => {
      db.run(index, err => {
        if (err && !err.message.includes('already exists')) {
          logger.error('Error creating index:', err);
        }
      });
    });

    logger.info('📊 Database migrations completed');
    
    // Clean up expired tokens on startup
    setTimeout(() => {
      cleanupExpiredTokens();
    }, 1000);
  });
};

/* ---------- Utility Functions ---------- */
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  const refreshToken = jwt.sign(
    { id: user.id, type: 'refresh' },
    REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_EXPIRES_IN }
  );

  return { accessToken, refreshToken };
};

const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

const auditLog = (userId, action, resource, details, req) => {
  db.run(
    'INSERT INTO audit_logs (user_id, action, resource, details, ip_address, user_agent, request_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [
      userId,
      action,
      resource,
      JSON.stringify(details),
      req.ip || req.connection.remoteAddress,
      req.get('User-Agent'),
      req.id
    ],
    (err) => {
      if (err) logger.error('Audit log error:', err);
    }
  );
};

const isAccountLocked = (user) => {
  if (!user.locked_until) return false;
  return new Date() < new Date(user.locked_until);
};

const lockAccount = (userId, minutes = 30) => {
  const lockUntil = new Date(Date.now() + minutes * 60 * 1000);
  db.run(
    'UPDATE usuarios SET locked_until = ? WHERE id = ?',
    [lockUntil.toISOString(), userId],
    (err) => {
      if (err) logger.error('Error locking account:', err);
    }
  );
};

const incrementFailedAttempts = (userId) => {
  db.run(
    'UPDATE usuarios SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
    [userId],
    function(err) {
      if (err) {
        logger.error('Error incrementing failed attempts:', err);
        return;
      }
      
      db.get('SELECT failed_login_attempts FROM usuarios WHERE id = ?', [userId], (err, row) => {
        if (!err && row && row.failed_login_attempts >= 5) {
          lockAccount(userId);
          logger.warn(`Account locked for user ${userId} after ${row.failed_login_attempts} failed attempts`);
        }
      });
    }
  );
};

const resetFailedAttempts = (userId) => {
  db.run(
    'UPDATE usuarios SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?',
    [userId]
  );
};

const cleanupExpiredTokens = () => {
  db.run('DELETE FROM refresh_tokens WHERE expires_at < datetime("now")', (err) => {
    if (err) logger.error('Error cleaning refresh tokens:', err);
  });
  
  db.run('DELETE FROM sessions WHERE expires_at < datetime("now")', (err) => {
    if (err) logger.error('Error cleaning sessions:', err);
  });
};

// Cleanup = every hour.
setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

/* ---------- Apply Rate Limiting ---------- */
app.use('/api/', generalLimiter);
app.use('/api/', speedLimiter);

/* ==========================================================
 *  ROUTES
 * ========================================================== */

/* Health Check */
app.get('/api/saude', (req, res) => {
  res.json({
    ok: true,
    ts: Date.now(),
    version: '3.0.0',
    node: process.version,
    environment: process.env.NODE_ENV || 'development'
  });
});

/* User Registration */
app.post('/api/usuarios',
  createAccountLimiter,
  sanitizeBody,
  [
    body('nome').isLength({ min: 2, max: 100 }).trim()
      .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/),
    body('cpf').isLength({ min: 11, max: 11 }).isNumeric(),
    body('email').isEmail().normalizeEmail().isLength({ max: 255 }),
    body('senha').isLength({ min: 6, max: 72 })
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { nome, cpf, email, senha } = req.body;

    const { error } = schemas.cadastro.validate(req.body);
    if (error) {
      logSecurityEvent('INVALID_REGISTRATION_DATA', req, { error: error.message });
      return res.status(400).json({ success: false, message: error.message });
    }

    try {
      const saltRounds = 12;
      const hash = await bcrypt.hash(senha, saltRounds);

      db.run(
        'INSERT INTO usuarios (nome, cpf, email, senha) VALUES (?, ?, ?, ?)',
        [nome, cpf, email, hash],
        function (err) {
          if (err) {
            if (err.message.includes('UNIQUE')) {
              logSecurityEvent('DUPLICATE_REGISTRATION', req, { email, cpf });
              return res.status(409).json({
                success: false,
                message: 'CPF ou e-mail já cadastrado'
              });
            }
            logger.error('Registration error:', err);
            return res.status(500).json({ success: false, message: 'Erro ao criar usuário' });
          }

          auditLog(this.lastID, 'USER_CREATED', 'usuarios', { email }, req);
          
          res.status(201).json({
            success: true,
            id: this.lastID,
            message: 'Usuário criado com sucesso'
          });

          logger.info(`Novo usuário #${this.lastID} (${email})`);
        }
      );
    } catch (error) {
      logger.error('Password hashing error:', error);
      res.status(500).json({ success: false, message: 'Erro interno do servidor' });
    }
  })
);

/* Enhanced Login with JWT */
app.post('/api/auth/login',
  authLimiter,
  sanitizeBody,
  [
    body('email').isEmail().normalizeEmail(),
    body('senha').isLength({ min: 1 })
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { email, senha } = req.body;

    db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
      if (err) {
        logger.error('Login database error:', err);
        return res.status(500).json({ success: false, message: 'Erro interno do servidor' });
      }

      const genericError = 'Credenciais inválidas';

      if (!user) {
        logSecurityEvent('LOGIN_ATTEMPT_INVALID_USER', req, { email });
        return res.status(401).json({ success: false, message: genericError });
      }

      if (isAccountLocked(user)) {
        logSecurityEvent('LOGIN_ATTEMPT_LOCKED_ACCOUNT', req, { userId: user.id });
        return res.status(423).json({
          success: false,
          message: 'Conta temporariamente bloqueada devido a muitas tentativas falhas'
        });
      }

      if (user.is_active === 0) {
        logSecurityEvent('LOGIN_ATTEMPT_INACTIVE_ACCOUNT', req, { userId: user.id });
        return res.status(403).json({
          success: false,
          message: 'Conta desativada. Entre em contato com o suporte.'
        });
      }

      try {
        const isPasswordValid = await bcrypt.compare(senha, user.senha);

        if (!isPasswordValid) {
          incrementFailedAttempts(user.id);
          logSecurityEvent('LOGIN_FAILED', req, { userId: user.id });
          return res.status(401).json({ success: false, message: genericError });
        }

        // Successful login;
        resetFailedAttempts(user.id);
        
        const { accessToken, refreshToken } = generateTokens(user);

        // Store refresh token (hashed);
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        db.run(
          'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
          [user.id, hashToken(refreshToken), expiresAt.toISOString()],
          (err) => {
            if (err) logger.error('Error storing refresh token:', err);
          }
        );

        // Session storing.
        const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        db.run(
          'INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)',
          [user.id, hashToken(accessToken), req.ip, req.get('User-Agent'), sessionExpiry.toISOString()],
          (err) => {
            if (err) logger.error('Error storing session:', err);
          }
        );

        db.all(
          `SELECT cep, search_count, last_searched 
           FROM user_ceps 
           WHERE user_id = ? 
           ORDER BY search_count DESC, last_searched DESC 
           LIMIT 5`,
          [user.id],
          (err, ceps) => {
            if (err) {
              logger.error('Error fetching recent CEPs:', err);
              ceps = [];
            }

            auditLog(user.id, 'USER_LOGIN', 'auth', { ip: req.ip }, req);

            res.json({
              success: true,
              user: {
                id: user.id,
                nome: user.nome,
                email: user.email
              },
              accessToken,
              refreshToken,
              recentCeps: ceps || []
            });

            logger.info(`Login de ${email}`);
          }
        );
      } catch (error) {
        logger.error('Password comparison error:', error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor' });
      }
    });
  })
);

/* Token Refresh */
app.post('/api/auth/refresh',
  strictLimiter,
  [body('refreshToken').isLength({ min: 1 })],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    try {
      const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
      const tokenHash = hashToken(refreshToken);

      db.get(
        `SELECT rt.*, u.id, u.nome, u.email 
         FROM refresh_tokens rt 
         JOIN usuarios u ON rt.user_id = u.id 
         WHERE rt.token_hash = ? AND rt.expires_at > datetime('now')`,
        [tokenHash],
        (err, result) => {
          if (err) {
            logger.error('Refresh token database error:', err);
            return res.status(500).json({ success: false, message: 'Erro interno do servidor' });
          }

          if (!result) {
            logSecurityEvent('INVALID_REFRESH_TOKEN', req);
            return res.status(401).json({ success: false, message: 'Token de refresh inválido' });
          }

          const user = { id: result.id, nome: result.nome, email: result.email };
          const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

          const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
          db.run(
            'UPDATE refresh_tokens SET token_hash = ?, expires_at = ? WHERE id = ?',
            [hashToken(newRefreshToken), expiresAt.toISOString(), result.id]
          );

          auditLog(user.id, 'TOKEN_REFRESHED', 'auth', {}, req);

          res.json({
            success: true,
            accessToken,
            refreshToken: newRefreshToken
          });
        }
      );
    } catch (error) {
      logSecurityEvent('REFRESH_TOKEN_ERROR', req, { error: error.message });
      res.status(401).json({ success: false, message: 'Token de refresh inválido' });
    }
  })
);

/* Logout */
app.post('/api/auth/logout',
  authenticateToken,
  [body('refreshToken').optional()],
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (refreshToken) {
      const tokenHash = hashToken(refreshToken);
      db.run('DELETE FROM refresh_tokens WHERE token_hash = ?', [tokenHash]);
    }

    db.run('DELETE FROM sessions WHERE user_id = ?', [req.user.id]); //note: remove current session/sessions. {Security}
    
    auditLog(req.user.id, 'USER_LOGOUT', 'auth', {}, req);

    res.json({ success: true, message: 'Logout realizado com sucesso' });
  })
);

/* CEP to Coordinates - Public endpoint */
app.get('/api/geo/cep/:cep',
  [param('cep').matches(/^\d{8}$/)],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const cleanedCep = req.params.cep.replace(/\D/g, '');
    
    const { error } = schemas.cep.validate(cleanedCep);
    if (error) return res.status(400).json({ success: false, message: 'CEP inválido' });

    try {
      logger.info(`Buscando CEP ${cleanedCep} no ViaCEP`);
      const viaCepUrl = `https://viacep.com.br/ws/${cleanedCep}/json/`;
      const viaCepResponse = await axios.get(viaCepUrl, { 
        timeout: 5000,
        headers: { 'User-Agent': 'FitnessAPI/3.0.0' }
      });
      
      if (viaCepResponse.data.erro) {
        logger.warn(`CEP ${cleanedCep} não encontrado no ViaCEP`);
        return res.status(404).json({ success: false, message: 'CEP não encontrado' });
      }
      
      const { logradouro, bairro, localidade, uf } = viaCepResponse.data;
      
      // Multiple search strategies.
      const searchStrategies = [
        // Full address;
        [logradouro, bairro, localidade, uf, 'Brazil'].filter(Boolean).join(', '),
        // Neighborhood + City;
        [bairro, localidade, uf, 'Brazil'].filter(Boolean).join(', '),
        // Just city;
        [localidade, uf, 'Brazil'].filter(Boolean).join(', ')
      ];

      let nominatimResponse = null;
      let searchAddress = '';

      for (const strategy of searchStrategies) {
        if (!strategy) continue;
        
        const searchQuery = encodeURIComponent(strategy);
        const nominatimUrl = `https://nominatim.openstreetmap.org/search?q=${searchQuery}&format=json&limit=1&countrycodes=br`;
        
        logger.info(`Tentando geocodificação: ${strategy}`);
        
        try {
          const response = await axios.get(nominatimUrl, {
            headers: { 'User-Agent': 'FitnessAPI/3.0.0' },
            timeout: 5000
          });
          
          if (response.data.length > 0) {
            nominatimResponse = response;
            searchAddress = strategy;
            break;
          }
        } catch (error) {
          logger.warn(`Erro na estratégia de busca: ${strategy}`, error.message);
        }
      }

      if (!nominatimResponse || !nominatimResponse.data.length) {
        // Major FallBack - Hardcoded coords.
        const cityCoords = {
          'Belo Horizonte': { lat: -19.9245, lon: -43.9352 },
          'São Paulo': { lat: -23.5505, lon: -46.6333 },
          'Rio de Janeiro': { lat: -22.9068, lon: -43.1729 },
          'Brasília': { lat: -15.7801, lon: -47.9292 },
          'Salvador': { lat: -12.9777, lon: -38.5016 },
          'Fortaleza': { lat: -3.7327, lon: -38.5270 },
          'Curitiba': { lat: -25.4284, lon: -49.2733 },
          'Recife': { lat: -8.0476, lon: -34.8770 },
          'Porto Alegre': { lat: -30.0346, lon: -51.2177 },
          'Manaus': { lat: -3.1190, lon: -60.0217 },
          'Belém': { lat: -1.4558, lon: -48.4902 },
          'Goiânia': { lat: -16.6864, lon: -49.2643 },
          'Guarulhos': { lat: -23.4538, lon: -46.5333 },
          'Campinas': { lat: -22.9099, lon: -47.0626 },
          'Nova Iguaçu': { lat: -22.7556, lon: -43.4440 },
          'Maceió': { lat: -9.6662, lon: -35.7356 },
          'São Luís': { lat: -2.5307, lon: -44.3068 },
          'Natal': { lat: -5.7945, lon: -35.2110 },
          'Campo Grande': { lat: -20.4697, lon: -54.6201 },
          'Teresina': { lat: -5.0892, lon: -42.8019 },
          'João Pessoa': { lat: -7.1195, lon: -34.8450 },
          'Aracaju': { lat: -10.9472, lon: -37.0731 },
          'Contagem': { lat: -19.9386, lon: -44.0539 },
          'Uberlândia': { lat: -18.9186, lon: -48.2772 },
          'Nova Lima': { lat: -19.9868, lon: -43.8466 }
        };
        
        const coords = cityCoords[localidade];
        if (coords) {
          logger.info(`Usando coordenadas predefinidas para ${localidade}`);
          return res.json({
            success: true,
            lat: coords.lat,
            lon: coords.lon,
            endereco: `${localidade} - ${uf}`,
            aproximado: true
          });
        }
        
        return res.status(404).json({ 
          success: false, 
          message: 'Não foi possível determinar as coordenadas deste CEP' 
        });
      }
      
      const { lat, lon } = nominatimResponse.data[0];
      
      logger.info(`Coordenadas encontradas para CEP ${cleanedCep}: ${lat}, ${lon}`);
      
      res.json({ 
        success: true, 
        lat: Number(lat), 
        lon: Number(lon), 
        endereco: searchAddress
      });
      
    } catch (error) {
      logger.error('Erro ao buscar CEP:', error.message);
      
      if (error.code === 'ECONNABORTED') {
        return res.status(503).json({ 
          success: false, 
          message: 'Serviço de CEP temporariamente indisponível. Tente novamente.' 
        });
      }
      
      res.status(503).json({ 
        success: false, 
        message: 'Serviço de geolocalização temporariamente indisponível' 
      });
    }
  })
);

/* Find Parks - ( Requires authentication ) */
app.get('/api/parques',
  authenticateToken,
  [
    query('cep').matches(/^\d{8}$/),
    query('raio').optional().isInt({ min: 500, max: 10000 })
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const cep = req.query.cep.replace(/\D/g, '');
    const raio = parseInt(req.query.raio) || 3000;

    const { error } = schemas.parques.validate({ cep, raio });
    if (error) return res.status(400).json({ success: false, message: error.message });

    try {
      const geoResponse = await axios.get(`http://localhost:${PORT}/api/geo/cep/${cep}`);
      const { lat, lon } = geoResponse.data;

      // Save-to-history.
      db.run(
        `INSERT INTO user_ceps (user_id, cep, search_count, last_searched)
         VALUES (?, ?, 1, CURRENT_TIMESTAMP)
         ON CONFLICT(user_id, cep) DO UPDATE SET
           search_count = search_count + 1,
           last_searched = CURRENT_TIMESTAMP`,
        [req.user.id, cep],
        (err) => {
          if (err) logger.error('Erro ao salvar histórico de CEP:', err);
        }
      );

      auditLog(req.user.id, 'SEARCH_PARKS', 'parques', { cep, raio }, req);

      const overpassQuery = `
        [out:json][timeout:25];
        (
          node["leisure"~"^(park|garden|playground|nature_reserve)$"](around:${raio},${lat},${lon});
          way["leisure"~"^(park|garden|playground|nature_reserve)$"](around:${raio},${lat},${lon});
          relation["leisure"~"^(park|garden|playground|nature_reserve)$"](around:${raio},${lat},${lon});
          node["tourism"="park"](around:${raio},${lat},${lon});
          way["tourism"="park"](around:${raio},${lat},${lon});
        );
        out center;`;

      const { data } = await axios.post(
        'https://overpass-api.de/api/interpreter',
        `data=${encodeURIComponent(overpassQuery)}`,
        { 
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 30000
        }
      );
      
      logger.info(`Overpass API retornou ${data.elements.length} elementos`);

      const parques = data.elements
        .filter(e => {
          if (!e.tags?.name || e.tags.name === 'Parque sem nome') return false;
          const lat = e.lat || e.center?.lat;
          const lon = e.lon || e.center?.lon;
          return lat && lon;
        })
        .map(e => ({
          id: e.id,
          nome: sanitizeInput(e.tags.name),
          latitude: e.lat || e.center?.lat,
          longitude: e.lon || e.center?.lon,
          descricao: e.tags.description ? sanitizeInput(e.tags.description) : null,
          abertura: e.tags.opening_hours || null,
          tipo: e.tags.leisure || e.tags.tourism || 'park',
          website: e.tags.website || null
        }));

      logger.info(`Encontrados ${parques.length} parques próximos ao CEP ${cep}`);

      res.json({ 
        success: true, 
        parques,
        centro: { lat, lon },
        endereco: geoResponse.data.endereco,
        aproximado: geoResponse.data.aproximado || false,
        cep,
        raio
      });
      
    } catch (error) {
      if (error.response?.status === 404) {
        return res.status(404).json({ success: false, message: 'CEP não encontrado' });
      }
      logger.error('Erro ao buscar parques:', error.message);
      res.status(500).json({ success: false, message: 'Erro ao buscar parques' });
    }
  })
);

/* Get User's CEP History - [Protected] */
app.get('/api/usuarios/:userId/ceps',
  authenticateToken,
  [param('userId').isInt({ min: 1 })],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.userId);

    if (userId !== req.user.id) {
      logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', req, {
        requestedUserId: userId,
        authenticatedUserId: req.user.id
      });
      return res.status(403).json({ success: false, message: 'Acesso negado' });
    }

    db.all(
      `SELECT cep, search_count, last_searched 
       FROM user_ceps 
       WHERE user_id = ? 
       ORDER BY search_count DESC, last_searched DESC 
       LIMIT 10`,
      [userId],
      (err, ceps) => {
        if (err) {
          logger.error('Erro ao buscar histórico de CEPs:', err);
          return res.status(500).json({ success: false, message: 'Erro ao buscar histórico' });
        }

        res.json({ success: true, ceps: ceps || [] });
      }
    );
  })
);

/* Clear User's CEP History - [Protected] */
app.delete('/api/usuarios/:userId/ceps',
  authenticateToken,
  [param('userId').isInt({ min: 1 })],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.userId);

    if (userId !== req.user.id) {
      logSecurityEvent('UNAUTHORIZED_DELETE_ATTEMPT', req, {
        requestedUserId: userId,
        authenticatedUserId: req.user.id
      });
      return res.status(403).json({ success: false, message: 'Acesso negado' });
    }

    db.run('DELETE FROM user_ceps WHERE user_id = ?', [userId], function(err) {
      if (err) {
        logger.error('Erro ao limpar histórico:', err);
        return res.status(500).json({ success: false, message: 'Erro ao limpar histórico' });
      }

      auditLog(userId, 'CLEAR_CEP_HISTORY', 'user_ceps', { deleted: this.changes }, req);

      res.json({ 
        success: true, 
        deleted: this.changes,
        message: 'Histórico limpo com sucesso'
      });
    });
  })
);

/* Get Active Sessions */
app.get('/api/usuarios/:userId/sessions',
  authenticateToken,
  [param('userId').isInt({ min: 1 })],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.userId);

    if (userId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Acesso negado' });
    }

    db.all(
      `SELECT id, ip_address, user_agent, created_at, expires_at, last_activity
       FROM sessions
       WHERE user_id = ? AND expires_at > datetime('now')
       ORDER BY created_at DESC`,
      [userId],
      (err, sessions) => {
        if (err) {
          logger.error('Error fetching sessions:', err);
          return res.status(500).json({ success: false, message: 'Erro ao buscar sessões' });
        }

        res.json({ success: true, sessions: sessions || [] });
      }
    );
  })
);

/* Revoke Session */
app.delete('/api/usuarios/:userId/sessions/:sessionId',
  authenticateToken,
  [
    param('userId').isInt({ min: 1 }),
    param('sessionId').isInt({ min: 1 })
  ],
  handleValidationErrors,
  asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.userId);
    const sessionId = parseInt(req.params.sessionId);

    if (userId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Acesso negado' });
    }

    db.run(
      'DELETE FROM sessions WHERE id = ? AND user_id = ?',
      [sessionId, userId],
      function(err) {
        if (err) {
          logger.error('Error revoking session:', err);
          return res.status(500).json({ success: false, message: 'Erro ao revogar sessão' });
        }

        if (this.changes === 0) {
          return res.status(404).json({ success: false, message: 'Sessão não encontrada' });
        }

        auditLog(userId, 'SESSION_REVOKED', 'sessions', { sessionId }, req);

        res.json({ success: true, message: 'Sessão revogada com sucesso' });
      }
    );
  })
);

/* Security Info Endpoint */
app.get('/api/security/info',
  authenticateToken,
  asyncHandler(async (req, res) => {
    db.get(
      `SELECT failed_login_attempts, locked_until, last_login
       FROM usuarios WHERE id = ?`,
      [req.user.id],
      (err, info) => {
        if (err) {
          logger.error('Error fetching security info:', err);
          return res.status(500).json({ success: false, message: 'Erro ao buscar informações' });
        }

        res.json({
          success: true,
          securityInfo: {
            failedAttempts: info.failed_login_attempts,
            isLocked: isAccountLocked(info),
            lockedUntil: info.locked_until,
            lastLogin: info.last_login
          }
        });
      }
    );
  })
);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => {
  logSecurityEvent('ROUTE_NOT_FOUND', req);
  res.status(404).json({ success: false, message: 'Rota não encontrada' });
});

/* Global Error Handler */
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  
  // Security-relevant errors;
  if (err.message && (err.message.includes('JSON') || err.message.includes('token'))) {
    logSecurityEvent('APPLICATION_ERROR', req, { error: err.message });
  }

  const message = process.env.NODE_ENV === 'production' 
    ? 'Erro interno do servidor' 
    : err.message;

  res.status(500).json({ success: false, message });
});

/* Graceful Shutdown */
const gracefulShutdown = () => {
  logger.info('Shutting down gracefully...');

  cleanupExpiredTokens();
  
  db.close((err) => {
    if (err) logger.error('Error closing database:', err);
    process.exit(0);
  });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

/* Start */
runMigrations();

app.listen(PORT, () => {
  logger.info(`🚀 Secure Fitness API running on http://localhost:${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Node version: ${process.version}`);
});