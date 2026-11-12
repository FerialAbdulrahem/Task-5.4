import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import bookingRoutes from './routes/bookings.js';
import userRoutes from './routes/users.js';
import maintenanceRoutes from './routes/maintenance.js';
import { csrfProtection, csrfTokenHandler } from './middleware/csrf.js';
import { maintenanceLimiter } from './middleware/rateLimit.js';

const app = express();

app.use(morgan('dev'));
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());                       // before CSRF middleware

app.get('/api/health', (req, res) => res.json({ ok: true }));

// DoS: first, so floods get 429 even without a CSRF token
app.use('/api/maintenance', maintenanceLimiter);

// CSRF: token endpoint (GET) + protection on all state-changing /api requests
app.get('/api/csrf-token', csrfTokenHandler);
app.use('/api', csrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/users', userRoutes);
app.use('/api/maintenance', maintenanceRoutes);

app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || err.statusCode || 500).json({ message: err.message || 'Server Error' });
});

export default app;