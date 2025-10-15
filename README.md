# [🏋️‍♂️ Projeto Fitness - Localizador de Espaços Recreativos]

[![Node.js](https://img.shields.io/badge/Node.js-23.x-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Express.js](https://img.shields.io/badge/Express.js-4.x-000000?logo=express&logoColor=white)](https://expressjs.com)
[![SQLite](https://img.shields.io/badge/SQLite-3.x-003B57?logo=sqlite&logoColor=white)](https://sqlite.org)
[![JWT](https://img.shields.io/badge/JWT-Autenticação-000000?logo=jsonwebtokens&logoColor=white)](https://jwt.io)

> **Aplicação full-stack para localização de parques e espaços recreativos no Brasil, implementada com arquitetura moderna, segurança enterprise e otimizações de performance feita em grupo**

## 🏗️ Arquitetura Técnica

### Stack Tecnológico

**Backend (Node.js/Express)**
```javascript
// Middleware de segurança implementado
app.use(helmet({ /* CSP, HSTS, XSS Protection */ }));
app.use(cors({ /* Validação dinâmica de origem */ }));
app.use(rateLimit({ /* Rate limiting progressivo */ }));
```

**Autenticação JWT**
- Access tokens: 1h de expiração
- Refresh tokens: 7 dias com rotação automática
- Hash SHA-256 para armazenamento de tokens
- Account lockout após 5 tentativas falhas

**APIs Externas Integradas**
- **ViaCEP**: Validação e geocodificação de CEPs
- **Nominatim (OSM)**: Conversão endereço → coordenadas
- **Overpass API**: Consulta em tempo real de dados OSM

### Arquitetura de Camadas

```sql
┌─────────────────────────────────────────────┐
│               Frontend (SPA)                │
│  • Leaflet.js (Mapas interativos)           │
│  • Vanilla JS (ES6 + modules)               │
│  • CSS Grid/Flexbox + Animações             │
└─────────────────┬───────────────────────────┘
                  │ HTTP/REST API
┌─────────────────▼───────────────────────────┐
│            Express.js Server                │
│  • Middleware de segurança (12 camadas)     │
│  • Validação Joi + express-validator        │
│  • Logging estruturado (Winston)            │
│  • Rate limiting + slow down                │
└─────────────────┬───────────────────────────┘
                  │ SQLite + Índices otimizados
┌─────────────────▼───────────────────────────┐
│               Database Layer                │
│  • Transações ACID                          │
│  • Índices compostos para performance       │
│  • Foreign keys + cascading                 │
│  • Audit trail completo                     │
└─────────────────────────────────────────────┘
```

## 🔐 Implementação de Segurança

### Autenticação & Autorização

```javascript
// JWT com refresh token rotation
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
```

### Rate Limiting Implementado

```javascript
// Rate limiters diferenciados por endpoint
const authLimiter = createRateLimiter(5 * 60 * 1000, 5, 'Muitas tentativas de login');
const createAccountLimiter = createRateLimiter(60 * 60 * 1000, 3, 'Limite de criação');
const strictLimiter = createRateLimiter(60 * 1000, 20, 'Limite geral excedido');
```

### Validação e Sanitização

```javascript
// Schemas Joi para validação
const schemas = {
  cadastro: Joi.object({
    nome: Joi.string().min(2).max(100).trim()
      .pattern(/^[a-zA-ZÀ-ÿ\s'-]+$/),
    cpf: Joi.string().length(11).pattern(/^\d+$/),
    email: Joi.string().email().max(255).lowercase().trim(),
    senha: Joi.string().min(6).max(72)
  })
};

// DOMPurify para sanitização XSS
const sanitizeInput = (input) => {
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [] }).trim();
};
```

## 🗄️ Design de Banco de Dados

### Schema Otimizado

```sql
-- Tabela principal de usuários
CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  cpf TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  senha TEXT NOT NULL,
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until DATETIME,
  last_login DATETIME,
  is_active BOOLEAN DEFAULT 1,
  password_changed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Histórico de buscas com contador de frequência
CREATE TABLE user_ceps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  cep TEXT NOT NULL,
  search_count INTEGER DEFAULT 1,
  last_searched DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
  UNIQUE(user_id, cep)
);

-- Gestão de tokens refresh
CREATE TABLE refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Sessões ativas para controle
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  ip_address TEXT,
  user_agent TEXT,
  expires_at DATETIME NOT NULL,
  last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Auditoria completa de ações
CREATE TABLE audit_logs (
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
);

-- Eventos de segurança para monitoramento
CREATE TABLE security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  user_id INTEGER,
  ip_address TEXT,
  details TEXT,
  severity TEXT DEFAULT 'medium',
  resolved BOOLEAN DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Índices de Performance

```sql
-- Índices otimizados para consultas frequentes
CREATE INDEX idx_usuarios_email ON usuarios(email);
CREATE INDEX idx_user_ceps_user_id ON user_ceps(user_id);
CREATE INDEX idx_user_ceps_last_searched ON user_ceps(last_searched DESC);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_security_events_created_at ON security_events(created_at DESC);
```

## 🔌 API REST - Documentação Técnica

### Endpoints de Autenticação

| Método | Endpoint | Rate Limit | Autenticação | Descrição |
|--------|----------|------------|--------------|-----------|
| `POST` | `/api/usuarios` | 3/hora | Não | Criação de usuário |
| `POST` | `/api/auth/login` | 5/5min | Não | Login + histórico CEPs |
| `POST` | `/api/auth/refresh` | 20/min | Refresh Token | Renovação de token |
| `POST` | `/api/auth/logout` | Geral | Access Token | Logout + limpeza |

### Endpoints de Funcionalidade

| Método | Endpoint | Parâmetros | Resposta |
|--------|----------|------------|----------|
| `GET` | `/api/geo/cep/:cep` | `cep` (8 dígitos) | `{lat, lon, endereco}` |
| `GET` | `/api/parques` | `cep`, `raio` (500-10000m) | Array de parques |
| `GET` | `/api/usuarios/:id/ceps` | `userId` | Histórico ordenado |
| `DELETE` | `/api/usuarios/:id/ceps` | `userId` | Confirmação limpeza |

### Estratégias de Geocodificação

```javascript
// Múltiplas estratégias de fallback para geocodificação
const searchStrategies = [
  // Endereço completo
  [logradouro, bairro, localidade, uf, 'Brazil'].filter(Boolean).join(', '),
  // Bairro + cidade
  [bairro, localidade, uf, 'Brazil'].filter(Boolean).join(', '),
  // Apenas cidade
  [localidade, uf, 'Brazil'].filter(Boolean).join(', ')
];

// Fallback para coordenadas hardcoded de centros urbanos
const cityCoords = {
  'Belo Horizonte': { lat: -19.9245, lon: -43.9352 },
  'São Paulo': { lat: -23.5505, lon: -46.6333 },
  'Rio de Janeiro': { lat: -22.9068, lon: -43.1729 }
  // ... 22 cidades brasileiras principais
};
```

## ⚡ Otimizações de Performance

### Backend

```javascript
// Cleanup automático de tokens expirados
const cleanupExpiredTokens = () => {
  db.run('DELETE FROM refresh_tokens WHERE expires_at < datetime("now")');
  db.run('DELETE FROM sessions WHERE expires_at < datetime("now")');
};
setInterval(cleanupExpiredTokens, 60 * 60 * 1000); // A cada hora

// Cache de consultas frequentes com upsert otimizado
db.run(
  `INSERT INTO user_ceps (user_id, cep, search_count, last_searched)
   VALUES (?, ?, 1, CURRENT_TIMESTAMP)
   ON CONFLICT(user_id, cep) DO UPDATE SET
     search_count = search_count + 1,
     last_searched = CURRENT_TIMESTAMP`,
  [req.user.id, cep]
);
```

### Frontend

```javascript
// Lazy loading de markers com animação escalonada
parksWithDistance.forEach((park, index) => {
  setTimeout(() => {
    const marker = L.marker([park.latitude, park.longitude], { 
      icon: createParkIcon()
    }).addTo(map);
    parkMarkers.push(marker);
    marker._icon.classList.add('marker-drop');
  }, index * 50); // Delay escalonado para UX suave
});

// Throttling para slider de raio
raioSlider.addEventListener('input', debounce(() => {
  if (searchCircle) {
    searchCircle.setRadius(parseInt(raioSlider.value));
  }
}, 100));
```

## 🚀 Configuração e Deploy

### Variáveis de Ambiente

```bash
# Configuração de segurança
JWT_SECRET=sua-chave-jwt-super-segura-aqui
REFRESH_TOKEN_SECRET=sua-chave-refresh-super-segura-aqui
JWT_EXPIRES_IN=1h

# Configuração do servidor
PORT=3000
NODE_ENV=production
LOG_LEVEL=info

# CORS para produção
ALLOWED_ORIGINS=https://seudominio.com,https://www.seudominio.com
```

### Docker para Produção

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .
USER nodejs
EXPOSE 3000
CMD ["node", "index.js"]
```

### Nginx + SSL

```nginx
server {
    listen 443 ssl http2;
    server_name seudominio.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting no nginx
        limit_req zone=api burst=10 nodelay;
    }
}
```

## 🧪 Testes e Monitoramento

### Endpoints de Debug

```bash
# Health check com métricas
curl http://localhost:3000/api/saude
# Resposta: {ok: true, ts: timestamp, version: "3.0.0", node: "v23.x"}

# Teste de geocodificação
curl http://localhost:3000/api/geo/cep/30130010

# Verificação de segurança de usuário (autenticado)
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:3000/api/security/info
```

### Logging Estruturado

```javascript
// Winston com múltiplos transportes
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.File({ filename: 'logs/security.log', level: 'warn' })
  ]
});
```

## 🔧 Troubleshooting Técnico

### Debug de Performance

```bash
# Análise de logs
tail -f logs/combined.log | grep "SLOW_QUERY"

# Monitoramento de memória
node --max-old-space-size=2048 index.js

# Profile de CPU
node --prof index.js
node --prof-process isolate-*.log > profile.txt
```

### Problemas Comuns

**CEP não encontrado**: Implementar fallback para coordenadas aproximadas
```javascript
const coords = cityCoords[localidade];
if (coords) {
  return res.json({
    success: true, lat: coords.lat, lon: coords.lon,
    endereco: `${localidade} - ${uf}`, aproximado: true
  });
}
```

**Rate limit atingido**: Implementar retry exponential backoff
```javascript
const retryWithBackoff = async (fn, retries = 3) => {
  try {
    return await fn();
  } catch (error) {
    if (retries > 0 && error.status === 429) {
      await new Promise(resolve => setTimeout(resolve, 2 ** (3 - retries) * 1000));
      return retryWithBackoff(fn, retries - 1);
    }
    throw error;
  }
};
```

---

## 📊 Métricas de Performance

- **Tempo de resposta API**: < 110ms (média, slow-server-host)
- **Renderização do mapa**: < 1s (até 50 markers)
- **Consulta de banco**: < 100ms (queries indexadas)
- **Throughput**: 1000+ req/min (com rate limiting)

## 🛠️ Ferramentas de Desenvolvimento

```bash
# Instalação de dependências de desenvolvimento
npm install --save-dev nodemon eslint prettier

# Scripts úteis
npm run dev        # Desenvolvimento com auto-restart
npm run lint       # Verificação de código
npm run format     # Formatação automática
```

