import type { FastifyInstance  } from "fastify";
import argon2 from 'argon2';
import { prisma } from '../lib/prisma.js'; // live prismaclient, runs at runtime, does database actions, run queries
import { Prisma } from '../generated/prisma/index.js'; // Describes prisma, catches stuff like errors/types,
import crypto from "crypto";
import { requireAuth } from '../middleware/requireAuth.js';

export async function authRoutes(app: FastifyInstance) {
    app.post('/register', async (request, reply) => {
        const { email, password } = request.body as { email: string; password: string };
        if (!email || !password) {
            return reply.status(400).send({
                message: 'Email and password are required'
            });
        }

        try {
            const hashedPassword = await argon2.hash(password);

            const newUser = await prisma.user.create({
                data: {
                    email,
                    passwordHash: hashedPassword,
                },
            });

            return reply.status(201).send({
                message: 'User registered',
                user: { id: newUser.id, email: newUser.email }
            })
            
        } catch (err) {
            if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
                return reply.status(409).send({
                    message: 'Email is already registered'
                });
            }

            request.log.error(err);
            return reply.status(500).send({
                message: 'Failed to create account'
            });
        }
    });

    app.post('/login', async(request, reply) => {
        const { email, password } = request.body as { email: string; password: string };

        if (!email || !password) {
            return reply.status(400).send({
                message: 'Email or password are required'
            });
        }

        try {
            const user = await prisma.user.findUnique({
                where : { email },
            });

            if (!user) {
                return reply.status(401).send({
                    message: 'Invalid credential'
                });
            }

            const passwordValid = await argon2.verify(user.passwordHash, password);
            if (!passwordValid) {
                return reply.status(401).send({
                    message: 'Invalid credential'
                });
            }

            const sessionExpiration = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7)
            const sessionToken = crypto.randomBytes(32).toString("hex");
            const sessionHash = crypto.createHash("sha256").update(sessionToken).digest("hex");

            const session = await prisma.session.create({ 
                data: {
                    userId: user.id,
                    sessionHash,
                    expiresAt: sessionExpiration,
                },
            });

            reply.setCookie("session", sessionToken, {
                httpOnly: true,
                secure: true,
                sameSite: "lax",
                expires: sessionExpiration,
            });

            reply.status(200).send({
                message: 'Login successful'
            });

        } catch (err) {
            request.log.error(err);
            return reply.status(500).send({
                message: 'Invalid credentials'
            });
        }
    });

    app.post('/logout', { preHandler: requireAuth }, async (request, reply) => {
        const sessionToken = request.cookies.session!;
        const sessionHash = crypto.createHash("sha256").update(sessionToken).digest("hex");

        await prisma.session.updateMany({
            where: { sessionHash },
            data: { revokedAt: new Date() },
        });

        reply.clearCookie('session', {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
        });

        return reply.status(200).send({ message: 'Logout successful' });
    });

    app.get('/me', { preHandler: requireAuth }, async (request, reply) => {
        return reply.status(200).send({ user: request.user });
    })
}