import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { PrismaClient, Category, Transaction, User } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { TransactionStatus } from '@prisma/client';
import { z } from 'zod';

// Load environment variables
dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;

// Constants
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);

// Schemas for validation (Step 3)
const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

const transactionSchema = z.object({
  amount: z.number().positive(),
  description: z.string().min(1),
  categoryId: z.number().int().optional(),
});

const categorySchema = z.object({
  name: z.string().min(3).max(50),
  description: z.string().optional(),
});

// Middleware
app.use(express.json());

// --- Global Error Handling Middleware (Step 5) ---
// This middleware catches errors thrown by controllers/routes and returns a standardized response.
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Global Error Handler:', err.stack);
  
  // Handle Zod validation errors
  if (err.name === 'ZodError') {
    return res.status(400).json({ message: 'Validation failed', errors: err.issues });
  }

  // Handle Prisma errors (e.g., unique constraint violations P2002)
  if (err instanceof Error && (err as any).code === 'P2002') {
    return res.status(409).json({ message: 'Resource already exists.' });
  }

  // Default server error
  res.status(500).json({ message: 'Internal Server Error.', error: process.env.NODE_ENV === 'development' ? err.message : undefined });
});

// --- Authentication Middleware ---
const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.status(401).json({ message: 'Access Token Missing' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or Expired Token' });
    }
    // Attach user payload to request
    (req as any).user = user;
    next();
  });
};

// =====================================================
// --- Auth API Implementation ---
// =====================================================

// --- Registration API ---
app.post('/api/auth/register', async (req: Request, res: Response) => {
  const validation = registerSchema.safeParse(req.body);
  if (!validation.success) {
    throw new Error('Validation failed');
  }
  const { email, password, name } = validation.data;

  // Hash password
  const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

  // Create user
  const user = await prisma.user.create({
    data: {
      email,
      name,
      password: hashedPassword,
    },
  });

  // Optionally return a token upon successful registration
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

  res.status(201).json({ message: 'User registered successfully', user: { id: user.id, email: user.email }, token });
});

// --- Login API ---
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const validation = loginSchema.safeParse(req.body);
  if (!validation.success) {
    throw new Error('Validation failed');
  }
  const { email, password } = validation.data;

  // Find user by email
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  // Compare passwords
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  // Generate JWT token
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

  res.status(200).json({ message: 'Login successful', token });
});

// =====================================================
// --- Category API Implementation (Steps 1, 2, 3, 4, 5) ---
// =====================================================

// POST /api/categories - Create a new category
app.post('/api/categories', async (req: Request, res: Response) => {
  // 1. Validation
  const validation = categorySchema.safeParse(req.body);
  if (!validation.success) {
    // Throws ZodError, caught by global middleware
    throw new Error('Validation failed');
  }
  const { name, description } = validation.data;

  try {
    // 2. Implement Category Logic (CRUD)
    const category = await prisma.category.create({
      data: {
        name,
        description,
      },
    });
    
    // 3. Success response
    res.status(201).json({ message: 'Category created successfully', category });
  } catch (error) {
    // Prisma errors (like unique constraint violation) handled by global middleware
    throw error; 
  }
});

// GET /api/categories - Retrieve all categories
app.get('/api/categories', async (req: Request, res: Response) => {
  try {
    const categories = await prisma.category.findMany({
      orderBy: { name: 'asc' },
    });
    res.status(200).json({ categories });
  } catch (error) {
    throw error;
  }
});

// GET /api/categories/:id - Retrieve a single category
app.get('/api/categories/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ message: 'Invalid category ID.' });
  }

  try {
    const category = await prisma.category.findUnique({
      where: { id },
    });

    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }
    res.status(200).json({ category });
  } catch (error) {
    throw error;
  }
});

// PUT /api/categories/:id - Update an existing category
app.put('/api/categories/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  const validation = categorySchema.safeParse(req.body);
  
  if (!validation.success) {
    throw new Error('Validation failed');
  }
  const { name, description } = validation.data;

  try {
    const updatedCategory = await prisma.category.update({
      where: { id },
      data: {
        name,
        description,
      },
    });
    res.status(200).json({ message: 'Category updated successfully', category: updatedCategory });
  } catch (error) {
    // Catch not found errors or unique constraint errors
    throw error; 
  }
});

// DELETE /api/categories/:id - Delete a category
app.delete('/api/categories/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);

  try {
    // Note: Check for related transactions before deleting in a real app, 
    // but Prisma handles foreign key constraints if configured.
    const deletedCategory = await prisma.category.delete({
      where: { id },
    });
    res.status(204).send(); // No content on successful deletion
  } catch (error) {
    // This might catch a Foreign Key Constraint violation if transactions reference this category
    throw error;
  }
});

// =====================================================
// --- Transaction API Implementation ---
// =====================================================

// POST /api/transactions - Create a new transaction
app.post('/api/transactions', authenticateToken, async (req: Request, res: Response) => {
  // 1. Validation
  const validation = transactionSchema.safeParse(req.body);
  if (!validation.success) {
    // Throws ZodError, caught by global middleware
    throw new Error('Validation failed');
  }
  const { amount, description, categoryId } = validation.data;
  const userId = (req as any).user.id;

  try {
    // 2. Implement Transaction Management (Using Prisma Transaction)
    const transaction = await prisma.$transaction(async (tx) => {
      const newTransaction = await tx.transaction.create({
        data: {
          userId: userId,
          amount: parseFloat(amount.toFixed(2)), // Ensure proper decimal handling
          description: description,
          status: TransactionStatus.PENDING, // Start as pending
          categoryId: categoryId || null, // Link category if provided
        },
      });
      return newTransaction;
    });

    // 3. Success response
    res.status(201).json({ message: 'Transaction created successfully', transaction });

  } catch (error) {
    // 4. Transaction Error Handling (Prisma errors caught by global middleware)
    throw error;
  }
});

// GET /api/transactions - Retrieve user's transactions
app.get('/api/transactions', authenticateToken, async (req: Request, res: Response) => {
  const userId = (req as any).user.id;

  try {
    const transactions = await prisma.transaction.findMany({
      where: { userId: userId },
      orderBy: { date: 'desc' },
      include: { category: true }, // Include category details
    });
    
    res.status(200).json({ transactions });
  } catch (error) {
    throw error;
  }
});

// =====================================================
// --- Protected Route Example ---
// =====================================================
// This route now requires a valid JWT
app.get('/api/profile', authenticateToken, async (req: Request, res: Response) => {
  // req.user is attached by the middleware
  const userId = (req as any).user.id;

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ message: 'Access granted to protected route', user: { id: user.id, email: user.email } });
  } catch (error) {
    throw error;
  }
});

// Simple Health Check Route
app.get('/', (req: Request, res: Response) => {
  res.status(200).json({ message: 'API is running successfully!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
