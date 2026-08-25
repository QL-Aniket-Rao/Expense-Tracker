import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { TransactionStatus } from '@prisma/client';

// Load environment variables
dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;

// Constants
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);

// Middleware
app.use(express.json());

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

// --- Registration API ---
app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
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
  } catch (error) {
    console.error('Registration error:', error);
    // Handle unique constraint violation (e.g., email already exists)
    if ((error as any).code === 'P2002') {
        return res.status(409).json({ message: 'Email already in use.' });
    }
    res.status(500).json({ message: 'Registration failed due to server error.' });
  }
});

// --- Login API ---
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email },
    });

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
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed due to server error.' });
  }
});

// =====================================================
// --- Transaction API Implementation ---
// =====================================================

// POST /api/transactions - Create a new transaction
app.post('/api/transactions', authenticateToken, async (req: Request, res: Response) => {
  const { amount, description } = req.body;
  const userId = (req as any).user.id;

  // 1. Transaction Validation
  if (typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ message: 'Invalid amount. Amount must be a positive number.' });
  }
  if (typeof description !== 'string' || description.trim() === '') {
    return res.status(400).json({ message: 'Description is required.' });
  }

  try {
    // 2. Implement Transaction Management (Using Prisma Transaction)
    const transaction = await prisma.$transaction(async (tx) => {
      // In a real application, we would check the user's balance here.
      // For this implementation, we simply create the transaction record.
      
      const newTransaction = await tx.transaction.create({
        data: {
          userId: userId,
          amount: parseFloat(amount.toFixed(2)), // Ensure proper decimal handling
          description: description,
          status: TransactionStatus.PENDING, // Start as pending
        },
      });
      
      // If complex logic was needed (e.g., updating a balance model), it would go here.
      // Example: await tx.account.update({ where: { userId }, data: { balance: { decrement: parseFloat(amount.toFixed(2)) } } });

      return newTransaction;
    });

    // 3. Success response
    res.status(201).json({ message: 'Transaction created successfully', transaction });

  } catch (error) {
    // 4. Transaction Error Handling
    console.error('Transaction creation error:', error);
    res.status(500).json({ message: 'Failed to process transaction due to a server error.' });
  }
});

// GET /api/transactions - Retrieve user's transactions
app.get('/api/transactions', authenticateToken, async (req: Request, res: Response) => {
  const userId = (req as any).user.id;

  try {
    const transactions = await prisma.transaction.findMany({
      where: { userId: userId },
      orderBy: { date: 'desc' },
    });
    
    res.status(200).json({ transactions });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ error: 'Failed to retrieve transactions.' });
  }
});

// =====================================================
// --- Protected Route Example ---
// =====================================================
// This route now requires a valid JWT
app.get('/api/profile', authenticateToken, async (req: Request, res: Response) => {
  // req.user is attached by the middleware
  const userId = (req as any).user.id;
  const userEmail = (req as any).user.email;

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ message: 'Access granted to protected route', user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error('Error accessing profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile data' });
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
