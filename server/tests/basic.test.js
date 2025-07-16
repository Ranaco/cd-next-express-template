import { describe, it, expect } from 'vitest';
import prisma from '../prisma/client.js';

describe('Basic Database Test', () => {
    it('should connect to database', async () => {
        // Simple test to verify database connection
        const result = await prisma.$queryRaw`SELECT 1 as test`;
        expect(result).toBeDefined();
        expect(result[0].test).toBe(1);
    });
});
