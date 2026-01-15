import type { FastifyRequest, FastifyReply } from "fastify";
import crypto from "crypto";
import { prisma } from "../lib/prisma.js";

declare module "fastify" {
    interface FastifyRequest {
        user?: {
            id: string;
            email: string;
            createdAt: Date;
        };
    }
}
export async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
    const sessionToken = request.cookies.session;

    if (!sessionToken) {
        return reply.status(401).send({ message: 'Unauthorized' });
    }

    const sessionHash = crypto.createHash("sha256").update(sessionToken).digest("hex");

    try {
        const session = await prisma.session.findUnique({
            where: { sessionHash },
            include: { user: true },
        });

        if (!session || session.expiresAt < new Date() || session.revokedAt) {
            return reply.status(401).send({ message: 'Unauthorized' });
        }

        request.user = {
            id: session.user.id,
            email: session.user.email,
            createdAt: session.user.createdAt
        };
        return;
    } catch (err) {
        request.log.error(err);
        return reply.status(500).send({ message: 'Internal server error' });
    }
}