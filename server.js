import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Enhanced CORS configuration - FIXED
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:4173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:4173',
    // Frontend public and private IPs
    'http://65.0.182.148:5173',
    'http://172.31.42.232:5173',
    'http://172.31.42.232:5174',
    'http://172.31.42.232:5175',
    // Backend public and private IPs
    'http://13.126.233.214:5000',
    'http://172.31.40.92:5000',
    // Add any other frontend URLs
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  optionsSuccessStatus: 200 // Some legacy browsers choke on 204
};

// Middleware - FIXED ORDER
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip || req.connection.remoteAddress}`);
  next();
});

// MongoDB connection with better error handling
const connectDB = async () => {
  try {
    // Check if MONGO_URL exists
    if (!process.env.MONGO_URL) {
      console.error("❌ MONGO_URL environment variable is not set!");
      console.log("💡 Please add MONGO_URL to your .env file");
      console.log("💡 Example: MONGO_URL=mongodb://localhost:27017/userdb");
      process.exit(1);
    }

    console.log("🔄 Attempting to connect to MongoDB...");
    console.log("🔗 MongoDB URL:", process.env.MONGO_URL.replace(/\/\/.*@/, '//***:***@')); // Hide credentials in logs
    
    await mongoose.connect(process.env.MONGO_URL);
    
    console.log("✅ Connected to MongoDB successfully");
    console.log(`🌐 Database: ${mongoose.connection.name}`);
    console.log(`🏠 Host: ${mongoose.connection.host}`);
    console.log(`🚪 Port: ${mongoose.connection.port}`);
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    console.log("💡 Common fixes:");
    console.log("   - Make sure MongoDB is running");
    console.log("   - Check your MONGO_URL in .env file");
    console.log("   - Verify network connectivity");
    process.exit(1);
  }
};

// Connect to database
connectDB();

// MongoDB connection event listeners
mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('🔄 MongoDB reconnected');
});

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Name is required'],
    trim: true,
    minlength: [1, 'Name cannot be empty']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  }
}, {
  timestamps: true // Add createdAt and updatedAt fields
});

// Add index for better performance
userSchema.index({ email: 1 });

const User = mongoose.model("User", userSchema);

// Health check endpoint - ENHANCED
app.get("/api/health", (req, res) => {
  const healthCheck = {
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    database: {
      status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
      name: mongoose.connection.name,
      host: mongoose.connection.host,
      port: mongoose.connection.port
    },
    server: {
      port: port,
      cors: corsOptions.origin,
      ip: req.ip || req.connection.remoteAddress
    }
  };
  console.log("🏥 Health check requested:", {
    status: healthCheck.status,
    database: healthCheck.database.status,
    uptime: healthCheck.uptime + 's',
    from: req.ip || req.connection.remoteAddress
  });
  res.json(healthCheck);
});

// API Routes with /api prefix and better error handling

// GET all users
app.get("/api/users", async (req, res) => {
  try {
    console.log("📋 Fetching all users...");
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    console.log(`✅ Found ${users.length} users`);
    res.json(users);
  } catch (err) {
    console.error("❌ Error fetching users:", err);
    res.status(500).json({ 
      message: "Failed to fetch users",
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// POST create new user
app.post("/api/users", async (req, res) => {
  try {
    console.log("➕ Creating new user:", { 
      name: req.body.name, 
      email: req.body.email,
      hasPassword: !!req.body.password 
    });
    
    // Validate required fields
    if (!req.body.name || !req.body.email || !req.body.password) {
      console.log("⚠️ Missing required fields");
      return res.status(400).json({ 
        message: "Name, email, and password are required" 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: req.body.email.toLowerCase() });
    if (existingUser) {
      console.log("⚠️ User already exists with email:", req.body.email);
      return res.status(400).json({ 
        message: "User with this email already exists" 
      });
    }

    const newUser = new User({
      name: req.body.name.trim(),
      email: req.body.email.toLowerCase().trim(),
      password: req.body.password
    });
    
    const savedUser = await newUser.save();
    console.log("✅ User created successfully:", savedUser._id);
    
    // Return user without password
    const { password, ...userWithoutPassword } = savedUser.toObject();
    res.status(201).json(userWithoutPassword);
  } catch (err) {
    console.error("❌ Error creating user:", err);
    
    // Handle validation errors
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        message: "Validation failed", 
        errors 
      });
    }
    
    // Handle duplicate key error
    if (err.code === 11000) {
      return res.status(400).json({ 
        message: "User with this email already exists" 
      });
    }
    
    res.status(500).json({ 
      message: "Failed to create user",
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// GET user by ID
app.get("/api/users/:id", async (req, res) => {
  try {
    console.log("👤 Fetching user by ID:", req.params.id);
    
    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.log("⚠️ Invalid user ID format:", req.params.id);
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      console.log("⚠️ User not found:", req.params.id);
      return res.status(404).json({ message: "User not found" });
    }
    
    console.log("✅ User found:", user.name);
    res.json([user]); // Return as array for frontend consistency
  } catch (err) {
    console.error("❌ Error fetching user:", err);
    res.status(500).json({ 
      message: "Failed to fetch user",
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// PUT update user
app.put("/api/users/:id", async (req, res) => {
  try {
    console.log("✏️ Updating user:", req.params.id, { 
      name: req.body.name, 
      email: req.body.email,
      hasPassword: !!req.body.password 
    });
    
    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.log("⚠️ Invalid user ID format:", req.params.id);
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    // Validate required fields
    if (!req.body.name || !req.body.email || !req.body.password) {
      console.log("⚠️ Missing required fields for update");
      return res.status(400).json({ 
        message: "Name, email, and password are required" 
      });
    }

    // Check if email is taken by another user
    const existingUser = await User.findOne({ 
      email: req.body.email.toLowerCase(),
      _id: { $ne: req.params.id }
    });
    
    if (existingUser) {
      console.log("⚠️ Email already taken by another user:", req.body.email);
      return res.status(400).json({ 
        message: "Email is already taken by another user" 
      });
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        name: req.body.name.trim(),
        email: req.body.email.toLowerCase().trim(),
        password: req.body.password
      },
      { 
        new: true, 
        runValidators: true 
      }
    ).select('-password');
    
    if (!updatedUser) {
      console.log("⚠️ User not found for update:", req.params.id);
      return res.status(404).json({ message: "User not found" });
    }
    
    console.log("✅ User updated successfully:", updatedUser.name);
    res.json(updatedUser);
  } catch (err) {
    console.error("❌ Error updating user:", err);
    
    // Handle validation errors
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        message: "Validation failed", 
        errors 
      });
    }
    
    // Handle duplicate key error
    if (err.code === 11000) {
      return res.status(400).json({ 
        message: "Email is already taken by another user" 
      });
    }
    
    res.status(500).json({ 
      message: "Failed to update user",
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// DELETE user
app.delete("/api/users/:id", async (req, res) => {
  try {
    console.log("🗑️ Deleting user:", req.params.id);
    
    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.log("⚠️ Invalid user ID format:", req.params.id);
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    const deletedUser = await User.findByIdAndDelete(req.params.id);
    
    if (!deletedUser) {
      console.log("⚠️ User not found for deletion:", req.params.id);
      return res.status(404).json({ message: "User not found" });
    }
    
    console.log("✅ User deleted successfully:", deletedUser.name);
    res.json({ 
      message: "User deleted successfully", 
      deletedUser: {
        id: deletedUser._id,
        name: deletedUser.name,
        email: deletedUser.email
      }
    });
  } catch (err) {
    console.error("❌ Error deleting user:", err);
    res.status(500).json({ 
      message: "Failed to delete user",
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// Root endpoint redirect
app.get("/", (req, res) => {
  res.json({
    message: "User Management API",
    version: "1.0.0",
    environment: process.env.NODE_ENV || 'development',
    cors: corsOptions.origin,
    endpoints: {
      health: "/api/health",
      users: "/api/users",
      createUser: "POST /api/users",
      getUser: "GET /api/users/:id",
      updateUser: "PUT /api/users/:id",
      deleteUser: "DELETE /api/users/:id"
    }
  });
});

// 404 handler
app.use("*", (req, res) => {
  console.log("❌ 404 - Route not found:", req.originalUrl);
  res.status(404).json({ message: "Route not found" });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("💥 Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('📊 MongoDB connection closed');
    process.exit(0);
  });
});

// Start server on all interfaces
app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${port}/api/health`);
  console.log(`🔗 Public health check: http://13.126.233.214:${port}/api/health`);
  console.log(`📱 API Base: http://localhost:${port}/api`);
  console.log(`📱 Public API Base: http://13.126.233.214:${port}/api`);
  console.log(`🎯 CORS Origins: ${corsOptions.origin.join(', ')}`);
});
