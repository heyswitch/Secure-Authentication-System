import "dotenv/config";
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { authRoutes } from './routes/auth.routes.js'

const app = Fastify({ logger: true });

if (!process.env.COOKIE_SECRET) {
    throw new Error('COOKIE_SECRET environment variable is required');
}

// Register cookie plugin with a secret for signing
app.register(cookie, {
    secret: process.env.COOKIE_SECRET,
});

app.get('/', async () => {
    return { status: 'ok' };
});

app.register(authRoutes, { prefix: '/auth' });

export default app;
