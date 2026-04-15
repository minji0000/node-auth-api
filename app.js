const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = 3000;
const users = [];
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not set in .env");
}

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Express server is running on port 3000");
});

function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return res.status(401).json({
      message: "authorization header is required",
    });
  }

  const [scheme, token] = authorization.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      message: "invalid authorization format",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (error) {
    return res.status(401).json({
      message: "invalid or expired token",
    });
  }
}

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "email and password are required",
      });
    }

    const emailNormalized = email.trim().toLowerCase();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailNormalized)) {
      return res.status(400).json({
        message: "invalid email format",
      });
    }

    const existingUser = users.find(
      (user) => user.email === emailNormalized
    );

    if (existingUser) {
      return res.status(409).json({
        message: "email already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = {
      email: emailNormalized,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };

    users.push(user);

    return res.status(201).json({
      message: "signup successful",
      user: {
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    return res.status(500).json({
      message: "internal server error",
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "email and password are required",
      });
    }

    const emailNormalized = email.trim().toLowerCase();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailNormalized)) {
      return res.status(400).json({
        message: "invalid email format",
      });
    }

    const user = users.find(
      (savedUser) => savedUser.email === emailNormalized
    );

    if (!user) {
      return res.status(401).json({
        message: "invalid email or password",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: "invalid email or password",
      });
    }

    const token = jwt.sign({ email: user.email, userId: users.indexOf(user) }
    , JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.status(200).json({
      message: "login successful",
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: "internal server error",
    });
  }
});

app.get("/me", authenticateToken, (req, res) => {
  const user = users.find((savedUser) => savedUser.email === req.user.email);

  if (!user) {
    return res.status(404).json({
      message: "user not found",
    });
  }

  return res.status(200).json({
    user: {
      email: user.email,
      createdAt: user.createdAt,
    },
  });
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
