import { parse } from "url";
import next from "next";
import express from "express";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import cors from "cors";

import authRouter from './routers/auth_router.js';
import userRouter from './routers/user_router.js';

const PORT = parseInt(process.env.PORT || "3000", 10);
const dev = process.env.NODE_ENV !== "production";
console.log(`Starting server in ${dev ? 'development' : 'production'} mode on port ${PORT}`);
const app = next({ dev });
const handle = app.getRequestHandler();

const ipRateLimiter = rateLimit({
    limit: 100,
    windowMs: 60 * 1000,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            message: 'Too many requests, please try again later.'
        });
        if (req.rateLimit.used === req.rateLimit.limit + 1) {
            console.warn(`Rate limit exceeded for IP: ${req.ip}`);
        }
    }
});

const server = express();

server.disable('x-powered-by');
server.disable('etag');

if (process.env.NODE_ENV !== 'development') {
    server.use(ipRateLimiter);
}

server.set('trust proxy', 2);

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://localhost:3001'];

server.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);

        const isAllowed = allowedOrigins.some(allowed => {
            if (allowed.includes('*')) {
                const pattern = allowed.replace(/\*/g, '.*');
                return new RegExp(pattern).test(origin);
            }
            return allowed === origin;
        });

        if (isAllowed) {
            callback(null, origin);
        } else {
            console.warn(`[CORS] Blocked request from origin: ${origin}`);
            callback(new Error(`Origin ${origin} not allowed by CORS policy`));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Origin', 'Accept'],
    optionsSuccessStatus: 204
}));

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

if (process.env.NODE_ENV !== "development") {
    server.use(
        helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
                    styleSrc: [
                        "'self'",
                        "'unsafe-inline'",
                        "https://fonts.googleapis.com",
                    ],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'", "data:", "https://fonts.gstatic.com"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                }
            },
        })
    );
}

server.use(cookieParser());

server.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

server.use('/api/auth', authRouter);
server.use('/api/users', userRouter);

app.prepare().then(() => {
    server.use((req, res) => {
        const parsedUrl = parse(req.url || '', true);
        handle(req, res, parsedUrl);
    });

    server.listen(PORT, (err) => {
        if (err) throw err;
        console.log(`🚀 Server ready on http://localhost:${PORT}`);
        console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
        console.log(`> Server listening as ${dev ? "development" : process.env.NODE_ENV}`);
    });
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});
