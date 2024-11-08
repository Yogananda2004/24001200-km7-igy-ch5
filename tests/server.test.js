const express = require("express");
const { PrismaClient } = require("@prisma/client");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (user) => {
  return jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "1h",
  });
};

app.post("/auth/register", async (req, res) => {
  const { name, email, password, identity_type, identity_number, address } =
    req.body;

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser)
    return res.status(400).json({ message: "Email sudah terdaftar" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
      profiles: {
        create: {
          identity_type,
          identity_number,
          address,
        },
      },
    },
  });

  const token = generateToken(user);
  res.json({ token, user });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user)
    return res.status(400).json({ message: "Email atau password salah" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).json({ message: "Email atau password salah" });

  const token = generateToken(user);
  res.json({ token, user });
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ message: "Token tidak disediakan" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Token tidak valid" });
    req.user = decoded;
    next();
  });
};

app.get("/api/v1/secure-data", authenticateJWT, (req, res) => {
  res.json({ message: "Ini adalah data rahasia" });
});

describe("Integration Testing for API Endpoints", () => {
  it("should create a new user and profile", async () => {
    const response = await request(app).post("/api/v1/users").send({
      name: "John Doe",
      email: "john.doe@example.com",
      password: "password123",
      identity_type: "KTP",
      identity_number: "123456789",
      address: "Jl. Sudirman No. 1",
    });
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("id");
    expect(response.body.name).toBe("John Doe");
  });

  it("should get all users", async () => {
    const response = await request(app).get("/api/v1/users");
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
  });

  it("should create a new bank account", async () => {
    const user = await prisma.user.findFirst();
    const response = await request(app).post("/api/v1/accounts").send({
      userId: user.id,
      bank_name: "Bank XYZ",
      bank_account_number: "987654321",
      balance: 1000,
    });
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("id");
    expect(response.body.bank_name).toBe("Bank XYZ");
  });

  it("should get all bank accounts", async () => {
    const response = await request(app).get("/api/v1/accounts");
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
  });

  it("should create a new transaction", async () => {
    const accounts = await prisma.bankAccount.findMany();
    if (accounts.length >= 2) {
      const response = await request(app).post("/api/v1/transactions").send({
        source_account_id: accounts[0].id,
        destination_account_id: accounts[1].id,
        amount: 100,
      });
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("id");
      expect(response.body.amount).toBe(100);
    }
  });

  it("should get all transactions", async () => {
    const response = await request(app).get("/api/v1/transactions");
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
  });
});
