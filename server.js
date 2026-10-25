require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
const Razorpay = require("razorpay");
const admin = require("firebase-admin");

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});
let razorpay = null;

if (
  process.env.RAZORPAY_KEY_ID &&
  process.env.RAZORPAY_KEY_SECRET
) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
}
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";

// ============================================================
// FIREBASE
// ============================================================

let firebaseReady = false;

try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (raw) {
    const serviceAccount = require(
      require("path").resolve(raw)
    );

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });

    firebaseReady = true;
  }
} catch (e) {
  console.warn("Firebase push disabled:", e.message);
}

// ============================================================
// PUSH NOTIFICATIONS
// ============================================================

async function sendPushToUser(
  userId,
  title,
  body,
  data = {},
  type = "general"
) {
  try {
    await pool.query(
      `INSERT INTO notification_logs
       (user_id,title,body,type,data)
       VALUES($1,$2,$3,$4,$5)`,
      [
        userId,
        title,
        body,
        type,
        JSON.stringify(data),
      ]
    );

    if (!firebaseReady) return;

    const q = await pool.query(
      `SELECT token FROM push_tokens WHERE user_id=$1`,
      [userId]
    );

    if (!q.rowCount) return;

    const tokens = q.rows.map((r) => r.token);

    const resp =
      await admin.messaging().sendEachForMulticast({
        tokens,
        notification: {
          title,
          body,
        },
        data: Object.fromEntries(
          Object.entries(data).map(([k, v]) => [
            k,
            String(v),
          ])
        ),
      });

    const bad = [];

    resp.responses.forEach((r, i) => {
      if (
        !r.success &&
        (
          r.error?.code ===
            "messaging/registration-token-not-registered" ||
          r.error?.code ===
            "messaging/invalid-registration-token"
        )
      ) {
        bad.push(tokens[i]);
      }
    });

    if (bad.length) {
      await pool.query(
        `DELETE FROM push_tokens
         WHERE token=ANY($1::text[])`,
        [bad]
      );
    }
  } catch (e) {
    console.error("Push error:", e.message);
  }
}

// ============================================================
// BUSINESS CONSTANTS
// ============================================================

const DELIVERY_FEE = 30;
const DELIVERY_EARNING = 20;
const NEARKART_DELIVERY_SHARE = 10;
const CANCEL_SECONDS = 30;
const SETTLEMENT_DAYS = 7;

const money = (n) =>
  Number(Number(n).toFixed(2));

const commission = (sub) =>
  Math.floor(Number(sub) / 1000) * 10;

// ============================================================
// AUTH HELPERS
// ============================================================

function tokenFor(u) {
  return jwt.sign(
    {
      id: u.id,
      role: u.role,
      email: u.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";

    if (!h.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required",
      });
    }

    req.user = jwt.verify(
      h.slice(7),
      JWT_SECRET
    );

    next();
  } catch (e) {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

function roles(...allowed) {
  return (req, res, next) =>
    allowed.includes(req.user.role)
      ? next()
      : res.status(403).json({
          error: "Forbidden",
        });
}

function hashCode(v) {
  return crypto
    .createHash("sha256")
    .update(String(v))
    .digest("hex");
}

// ============================================================
// GMAIL OTP
// ============================================================

let transporter = null;

if (
  process.env.GMAIL_USER &&
  process.env.GMAIL_APP_PASSWORD
) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

async function sendOtp(email, code, purpose) {
  if (!transporter) {
    console.log(
      `[DEV OTP] ${email} -> ${code} (${purpose})`
    );
    return;
  }

  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: `NearKart ${purpose} OTP`,
    text:
      `Your NearKart OTP is ${code}. ` +
      `It is valid for 5 minutes and can be used once.`,
  });
}

// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    version: "2.1.0",
    pushNotifications: firebaseReady,
  });
});

// ============================================================
// REQUEST OTP
// ============================================================

app.post(
  "/api/auth/request-otp",
  async (req, res) => {
    try {
      const {
        email,
        purpose = "login",
      } = req.body;

      if (!email) {
        return res.status(400).json({
          error: "Email required",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      const allowedPurposes = [
        "login",
        "forgot_password",
        "register",
      ];

      if (!allowedPurposes.includes(purpose)) {
        return res.status(400).json({
          error: "Invalid OTP purpose",
        });
      }

      const code = String(
        Math.floor(
          100000 + Math.random() * 900000
        )
      );

      await pool.query(
        `INSERT INTO otp_codes
         (email,purpose,code_hash,expires_at)
         VALUES($1,$2,$3,NOW()+INTERVAL '5 minutes')`,
        [
          normalizedEmail,
          purpose,
          hashCode(code),
        ]
      );

      await sendOtp(
        normalizedEmail,
        code,
        purpose
      );

      res.json({
        message: "OTP sent to email",
      });
    } catch (e) {
      console.error(
        "Request OTP error:",
        e.message
      );

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// VERIFY OTP
// ============================================================

app.post(
  "/api/auth/verify-otp",
  async (req, res) => {
    try {
      const {
        email,
        code,
        purpose = "login",
      } = req.body;

      if (!email || !code) {
        return res.status(400).json({
          error: "Email and OTP required",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      const q = await pool.query(
        `SELECT *
         FROM otp_codes
         WHERE email=$1
           AND purpose=$2
           AND used=false
           AND expires_at>NOW()
         ORDER BY id DESC
         LIMIT 1`,
        [
          normalizedEmail,
          purpose,
        ]
      );

      if (!q.rowCount) {
        return res.status(400).json({
          error: "OTP expired or not found",
        });
      }

      const otp = q.rows[0];

      if (otp.attempts >= 5) {
        return res.status(429).json({
          error: "Too many attempts",
        });
      }

      if (
        otp.code_hash !==
        hashCode(code)
      ) {
        await pool.query(
          `UPDATE otp_codes
           SET attempts=attempts+1
           WHERE id=$1`,
          [otp.id]
        );

        return res.status(400).json({
          error: "Invalid OTP",
        });
      }

      // Mark OTP as used
      await pool.query(
        `UPDATE otp_codes
         SET used=true
         WHERE id=$1`,
        [otp.id]
      );

      // Forgot password OTP is NOT login OTP
      if (purpose === "forgot_password") {
        const userQ = await pool.query(
          `SELECT id,email,name,role
           FROM users
           WHERE email=$1`,
          [normalizedEmail]
        );

        if (!userQ.rowCount) {
          return res.status(404).json({
            error: "Account not found",
          });
        }

        return res.json({
          verified: true,
          purpose: "forgot_password",
          message:
            "OTP verified. You can now reset your password.",
        });
      }

      // Login OTP
      let u = (
        await pool.query(
          `SELECT *
           FROM users
           WHERE email=$1`,
          [normalizedEmail]
        )
      ).rows[0];

      // If user doesn't exist,
      // create customer account automatically.
      if (!u) {
        u = (
          await pool.query(
            `INSERT INTO users
             (role,name,email)
             VALUES('customer',$1,$2)
             RETURNING *`,
            [
              normalizedEmail.split("@")[0],
              normalizedEmail,
            ]
          )
        ).rows[0];
      }

      res.json({
        token: tokenFor(u),
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          email: u.email,
        },
      });
    } catch (e) {
      console.error(
        "Verify OTP error:",
        e.message
      );

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// RESET PASSWORD USING GMAIL OTP
// ============================================================

app.post(
  "/api/auth/reset-password",
  async (req, res) => {
    try {
      const {
        email,
        code,
        newPassword,
      } = req.body;

      if (
        !email ||
        !code ||
        !newPassword
      ) {
        return res.status(400).json({
          error:
            "Email, OTP and new password are required",
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          error:
            "Password must be at least 6 characters",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      // Find latest valid forgot-password OTP
      const q = await pool.query(
        `SELECT *
         FROM otp_codes
         WHERE email=$1
           AND purpose='forgot_password'
           AND used=false
           AND expires_at>NOW()
         ORDER BY id DESC
         LIMIT 1`,
        [normalizedEmail]
      );

      if (!q.rowCount) {
        return res.status(400).json({
          error:
            "OTP expired or not found",
        });
      }

      const otp = q.rows[0];

      if (otp.attempts >= 5) {
        return res.status(429).json({
          error: "Too many attempts",
        });
      }

      if (
        otp.code_hash !==
        hashCode(code)
      ) {
        await pool.query(
          `UPDATE otp_codes
           SET attempts=attempts+1
           WHERE id=$1`,
          [otp.id]
        );

        return res.status(400).json({
          error: "Invalid OTP",
        });
      }

      // Check account
      const userQ = await pool.query(
        `SELECT id
         FROM users
         WHERE email=$1`,
        [normalizedEmail]
      );

      if (!userQ.rowCount) {
        return res.status(404).json({
          error: "Account not found",
        });
      }

      // Hash new password
      const passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      // Update password
      await pool.query(
        `UPDATE users
         SET password_hash=$1
         WHERE email=$2`,
        [
          passwordHash,
          normalizedEmail,
        ]
      );

      // Mark OTP as used
      await pool.query(
        `UPDATE otp_codes
         SET used=true
         WHERE id=$1`,
        [otp.id]
      );

      res.json({
        message:
          "Password reset successfully",
      });
    } catch (e) {
      console.error(
        "Reset password error:",
        e.message
      );

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
        phone,
        role = "customer",
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password required",
        });
      }

      if (
        ![
          "customer",
          "shopkeeper",
          "delivery",
        ].includes(role)
      ) {
        return res.status(400).json({
          error: "Invalid role",
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const q = await pool.query(
        `INSERT INTO users
         (role,name,email,phone,password_hash)
         VALUES($1,$2,$3,$4,$5)
         RETURNING *`,
        [
          role,
          name,
          email.toLowerCase().trim(),
          phone || null,
          hash,
        ]
      );

      const u = q.rows[0];

      res.status(201).json({
        token: tokenFor(u),
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          email: u.email,
        },
      });
    } catch (e) {
      res.status(
        e.code === "23505"
          ? 409
          : 500
      ).json({
        error:
          e.code === "23505"
            ? "Email already registered"
            : e.message,
      });
    }
  }
);

// ============================================================
// PASSWORD LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const {
        email,
        password,
      } = req.body;

      const q = await pool.query(
        `SELECT *
         FROM users
         WHERE email=$1`,
        [email.toLowerCase().trim()]
      );

      if (
        !q.rowCount ||
        !q.rows[0].password_hash
      ) {
        return res.status(401).json({
          error: "Invalid login",
        });
      }

      const u = q.rows[0];

      if (
        !(await bcrypt.compare(
          password,
          u.password_hash
        ))
      ) {
        return res.status(401).json({
          error: "Invalid login",
        });
      }

      res.json({
        token: tokenFor(u),
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          email: u.email,
        },
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// PUSH TOKEN
// ============================================================

app.post(
  "/api/push/register-token",
  auth,
  async (req, res) => {
    try {
      const {
        token,
        platform,
      } = req.body;

      if (!token) {
        return res.status(400).json({
          error: "FCM token required",
        });
      }

      await pool.query(
        `INSERT INTO push_tokens
         (user_id,token,platform)
         VALUES($1,$2,$3)
         ON CONFLICT(token)
         DO UPDATE SET
           user_id=EXCLUDED.user_id,
           platform=EXCLUDED.platform,
           updated_at=NOW()`,
        [
          req.user.id,
          token,
          platform || null,
        ]
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.delete(
  "/api/push/register-token",
  auth,
  async (req, res) => {
    try {
      await pool.query(
        `DELETE FROM push_tokens
         WHERE user_id=$1
         AND token=$2`,
        [
          req.user.id,
          req.body.token,
        ]
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// NOTIFICATIONS
// ============================================================

app.get(
  "/api/notifications",
  auth,
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT
           id,
           title,
           body,
           type,
           data,
           created_at
         FROM notification_logs
         WHERE user_id=$1
         ORDER BY created_at DESC
         LIMIT 50`,
        [req.user.id]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ADMIN BROADCAST
// ============================================================

app.post(
  "/api/admin/notifications/broadcast",
  auth,
  roles("admin"),
  async (req, res) => {
    try {
      const {
        title,
        body,
        type = "announcement",
        data = {},
        roles: targetRoles = [
          "customer",
          "shopkeeper",
          "delivery",
        ],
      } = req.body;

      if (
        !title ||
        !body ||
        !Array.isArray(targetRoles) ||
        !targetRoles.length
      ) {
        return res.status(400).json({
          error:
            "title, body and target roles required",
        });
      }

      const q = await pool.query(
        `SELECT id
         FROM users
         WHERE role=ANY($1::text[])`,
        [targetRoles]
      );

      for (const u of q.rows) {
        await sendPushToUser(
          u.id,
          title,
          body,
          data,
          type
        );
      }

      res.json({
        ok: true,
        recipients: q.rowCount,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// NEARBY SHOPS
// ============================================================

app.get(
  "/api/shops/nearby",
  async (req, res) => {
    try {
      const lat = Number(
        req.query.lat
      );

      const lng = Number(
        req.query.lng
      );

      const radiusKm = Number(
        req.query.radiusKm || 10
      );

      if (
        !Number.isFinite(lat) ||
        !Number.isFinite(lng)
      ) {
        return res.status(400).json({
          error:
            "lat and lng are required",
        });
      }

      const q = await pool.query(
        `
        SELECT
          s.*,

          (
            6371 * acos(
              LEAST(
                1,
                GREATEST(
                  -1,

                  cos(radians($1))
                  * cos(radians(s.latitude))
                  * cos(
                      radians(s.longitude)
                      - radians($2)
                    )

                  + sin(radians($1))
                  * sin(radians(s.latitude))
                )
              )
            )
          ) AS distance_km,

          COALESCE(
            (
              SELECT COUNT(*)
              FROM products p
              WHERE p.shop_id=s.id
              AND p.active=true
            ),
            0
          ) AS product_count

        FROM shops s

        WHERE
          s.status='approved'
          AND s.latitude IS NOT NULL
          AND s.longitude IS NOT NULL

        HAVING
          (
            6371 * acos(
              LEAST(
                1,
                GREATEST(
                  -1,

                  cos(radians($1))
                  * cos(radians(s.latitude))
                  * cos(
                      radians(s.longitude)
                      - radians($2)
                    )

                  + sin(radians($1))
                  * sin(radians(s.latitude))
                )
              )
            )
          ) <= $3

        ORDER BY
          distance_km ASC,
          s.created_at DESC

        LIMIT 50
        `,
        [
          lat,
          lng,
          radiusKm,
        ]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ALL SHOPS
// ============================================================

app.get(
  "/api/shops",
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT *
         FROM shops
         WHERE status='approved'
         ORDER BY created_at DESC`
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// PRODUCT SEARCH
// ============================================================

app.get(
  "/api/products/search",
  async (req, res) => {
    try {
      const qText = String(
        req.query.q || ""
      ).trim();

      const category = String(
        req.query.category || ""
      ).trim();

      const q = await pool.query(
        `
        SELECT
          p.*,
          s.shop_name,
          s.category AS shop_category

        FROM products p

        JOIN shops s
          ON s.id=p.shop_id

        WHERE
          p.active=true
          AND s.status='approved'

          AND (
            $1=''
            OR p.name ILIKE '%'||$1||'%'
            OR COALESCE(
                p.description,
                ''
              ) ILIKE '%'||$1||'%'
          )

          AND (
            $2=''
            OR p.category=$2
            OR s.category=$2
          )

        ORDER BY
          p.created_at DESC

        LIMIT 100
        `,
        [
          qText,
          category,
        ]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// SHOP PRODUCTS
// ============================================================

app.get(
  "/api/shops/:id/products",
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT *
         FROM products
         WHERE shop_id=$1
         AND active=true
         ORDER BY created_at DESC`,
        [req.params.id]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// CREATE SHOP
// ============================================================

app.post(
  "/api/shops",
  auth,
  roles("shopkeeper"),
  async (req, res) => {
    try {
      const {
        shopName,
        category,
        gstNumber,
        panNumber,
        address,
        latitude,
        longitude,
        openingTime,
        closingTime,
        documents,
      } = req.body;

      const q = await pool.query(
        `INSERT INTO shops
         (
           owner_id,
           shop_name,
           category,
           gst_number,
           pan_number,
           address,
           latitude,
           longitude,
           opening_time,
           closing_time,
           documents
         )
         VALUES(
           $1,$2,$3,$4,$5,$6,
           $7,$8,$9,$10,$11
         )
         RETURNING *`,
        [
          req.user.id,
          shopName,
          category,
          gstNumber || null,
          panNumber || null,
          address || null,
          latitude || null,
          longitude || null,
          openingTime || null,
          closingTime || null,
          documents || {},
        ]
      );

      res.status(201).json(
        q.rows[0]
      );
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// CREATE PRODUCT
// ============================================================

app.post(
  "/api/shops/:id/products",
  auth,
  roles("shopkeeper", "admin"),
  async (req, res) => {
    try {
      const {
        name,
        description,
        category,
        price,
        stock,
        prescriptionRequired = false,
        images = [],
      } = req.body;

      const q = await pool.query(
        `INSERT INTO products
         (
           shop_id,
           name,
           description,
           category,
           price,
           stock,
           prescription_required,
           images
         )
         VALUES(
           $1,$2,$3,$4,
           $5,$6,$7,$8
         )
         RETURNING *`,
        [
          req.params.id,
          name,
          description || null,
          category || null,
          price,
          stock || 0,
          prescriptionRequired,
          JSON.stringify(images),
        ]
      );

      res.status(201).json(
        q.rows[0]
      );
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// CREATE ORDER
// ============================================================


app.post(
  "/api/orders",
  auth,
  roles("customer"),
  async (req, res) => {
    const client = await pool.connect();
    let transactionStarted = false;

    try {
      if (!razorpay) {
        return res.status(503).json({
          error: "Razorpay is not configured on the server.",
        });
      }

      const { shopId, items, address, prescriptionUrl } = req.body;

      if (!shopId || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({
          error: "shopId and items are required.",
        });
      }

      if (!address || typeof address !== "object" ||
          !String(address.fullAddress || "").trim()) {
        return res.status(400).json({
          error: "A delivery address is required.",
        });
      }

      const productIds = items.map((item) => String(item.productId || ""));
      if (
        productIds.some((id) => !id) ||
        new Set(productIds).size !== productIds.length
      ) {
        return res.status(400).json({
          error: "Invalid or duplicate products.",
        });
      }

      await client.query("BEGIN");
      transactionStarted = true;

      const shopQ = await client.query(
        `SELECT id FROM shops
         WHERE id=$1 AND status='approved'`,
        [shopId]
      );

      if (!shopQ.rowCount) {
        throw new Error("Shop not found or not approved.");
      }

      const productQ = await client.query(
        `SELECT *
         FROM products
         WHERE id=ANY($1::uuid[])
           AND shop_id=$2
           AND active=true
         FOR UPDATE`,
        [productIds, shopId]
      );

      if (productQ.rowCount !== items.length) {
        throw new Error("Some products are unavailable.");
      }

      let subtotal = 0;

      for (const item of items) {
        const product = productQ.rows.find(
          (p) => p.id === String(item.productId)
        );
        const qty = Number(item.quantity);

        if (!Number.isInteger(qty) || qty < 1 || qty > Number(product.stock)) {
          throw new Error(`Invalid stock or quantity for ${product.name}.`);
        }

        if (product.prescription_required && !prescriptionUrl) {
          throw new Error(
            `Prescription is required for ${product.name}.`
          );
        }

        subtotal += Number(product.price) * qty;
      }

      subtotal = money(subtotal);
      const shopCommission = commission(subtotal);
      const total = money(subtotal + DELIVERY_FEE);
      const cancelUntil = new Date(
        Date.now() + CANCEL_SECONDS * 1000
      );

      const orderQ = await client.query(
        `INSERT INTO orders
         (
           customer_id, shop_id, status, subtotal,
           delivery_fee, shop_commission, total,
           cancel_until, address, prescription_url,
           payment_status
         )
         VALUES ($1,$2,'pending',$3,$4,$5,$6,$7,$8,$9,'pending')
         RETURNING *`,
        [
          req.user.id,
          shopId,
          subtotal,
          DELIVERY_FEE,
          shopCommission,
          total,
          cancelUntil,
          address,
          prescriptionUrl || null,
        ]
      );

      const order = orderQ.rows[0];

      for (const item of items) {
        const product = productQ.rows.find(
          (p) => p.id === String(item.productId)
        );

        await client.query(
          `INSERT INTO order_items
           (order_id, product_id, quantity, unit_price)
           VALUES ($1,$2,$3,$4)`,
          [order.id, product.id, Number(item.quantity), product.price]
        );
      }

      // Razorpay requires the amount in paise, not rupees.
      const razorpayOrder = await razorpay.orders.create({
        amount: Math.round(total * 100),
        currency: "INR",
        receipt: String(order.id).replace(/-/g, "").slice(0, 40),
        notes: {
          nearkart_order_id: String(order.id),
          customer_id: String(req.user.id),
        },
      });

      await client.query(
        `INSERT INTO payments
         (order_id, provider, provider_order_id, amount, status, raw)
         VALUES ($1,'razorpay',$2,$3,'created',$4)`,
        [
          order.id,
          razorpayOrder.id,
          total,
          JSON.stringify({
            razorpayOrderId: razorpayOrder.id,
          }),
        ]
      );

      await client.query("COMMIT");
      transactionStarted = false;

      return res.status(201).json({
        orderId: order.id,
        keyId: process.env.RAZORPAY_KEY_ID,
        razorpayOrderId: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency,
        subtotal,
        deliveryFee: DELIVERY_FEE,
        total,
        shopCommission,
        paymentStatus: "created",
      });
    } catch (e) {
      if (transactionStarted) {
        await client.query("ROLLBACK");
      }

      console.error("Create order error:", e.message);

      return res.status(400).json({
        error: e.message || "Could not create order.",
      });
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/payments/razorpay/verify",
  auth,
  roles("customer"),
  async (req, res) => {
    const client = await pool.connect();
    let transactionStarted = false;

    try {
      const {
        orderId,
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      } = req.body;

      if (
        !razorpay ||
        !orderId ||
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          error: "Required payment details are missing.",
        });
      }

      // Verify signature on the server; never trust the app callback alone.
      const expectedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest("hex");

      const supplied = Buffer.from(razorpay_signature, "hex");
      const expected = Buffer.from(expectedSignature, "hex");

      if (
        supplied.length !== expected.length ||
        !crypto.timingSafeEqual(supplied, expected)
      ) {
        return res.status(400).json({
          error: "Razorpay signature verification failed.",
        });
      }

      await client.query("BEGIN");
      transactionStarted = true;

      const orderQ = await client.query(
        `SELECT *
         FROM orders
         WHERE id=$1 AND customer_id=$2
         FOR UPDATE`,
        [orderId, req.user.id]
      );

      if (!orderQ.rowCount) {
        throw new Error("Order not found.");
      }

      const order = orderQ.rows[0];

      const paymentQ = await client.query(
        `SELECT *
         FROM payments
         WHERE order_id=$1 AND provider='razorpay'
         FOR UPDATE`,
        [orderId]
      );

      if (!paymentQ.rowCount) {
        throw new Error("Razorpay payment record not found.");
      }

      const payment = paymentQ.rows[0];

      if (payment.provider_order_id !== razorpay_order_id) {
        throw new Error("Razorpay order ID does not match.");
      }

      // Idempotency: a repeated callback must not decrement stock twice.
      if (order.payment_status === "paid") {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.json({
          verified: true,
          orderId: order.id,
          paymentStatus: "paid",
          message: "Payment was already verified.",
        });
      }

      if (order.payment_status !== "pending") {
        throw new Error("This order is not awaiting payment.");
      }

      // Lock all ordered products and check stock again.
      const itemsQ = await client.query(
        `SELECT
           oi.product_id,
           oi.quantity,
           oi.unit_price,
           p.name,
           p.stock,
           p.shop_id
         FROM order_items oi
         JOIN products p ON p.id=oi.product_id
         WHERE oi.order_id=$1
         FOR UPDATE OF p`,
        [orderId]
      );

      if (!itemsQ.rowCount) {
        throw new Error("Order has no items.");
      }

      const stockIssue = itemsQ.rows.some(
        (item) => Number(item.stock) < Number(item.quantity)
      );

      // Record the verified payment even if stock has changed.
      // In that unusual case, hold the order for manual resolution.
      await client.query(
        `UPDATE payments
         SET status='paid',
             raw=$1
         WHERE id=$2`,
        [
          JSON.stringify({
            razorpay_order_id,
            razorpay_payment_id,
            signature_verified: true,
          }),
          payment.id,
        ]
      );

      if (stockIssue) {
        await client.query(
          `UPDATE orders
           SET payment_status='paid',
               status='payment_review'
           WHERE id=$1`,
          [orderId]
        );

        await client.query("COMMIT");
        transactionStarted = false;

        await sendPushToUser(
          req.user.id,
          "Payment received",
          "Your payment was verified. The order needs a stock review; please contact NearKart support.",
          { orderId, status: "payment_review" },
          "payment_review"
        );

        return res.json({
          verified: true,
          needsReview: true,
          orderId,
          paymentStatus: "paid",
          message: "Payment verified; order needs stock review.",
        });
      }

      for (const item of itemsQ.rows) {
        await client.query(
          `UPDATE products
           SET stock=stock-$1
           WHERE id=$2`,
          [Number(item.quantity), item.product_id]
        );
      }

      const shopCommission = Number(order.shop_commission);
      const subtotal = Number(order.subtotal);

      await client.query(
        `INSERT INTO financial_ledger
         (
           order_id, owner_type, owner_id, entry_type,
           amount, available_at
         )
         VALUES
         (
           $1, 'shopkeeper',
           (SELECT owner_id FROM shops WHERE id=$2),
           'shop_earning', $3, NOW()+INTERVAL '7 days'
         ),
         (
           $1, 'nearkart', NULL,
           'shop_commission', $4, NOW()
         ),
         (
           $1, 'delivery_pool', NULL,
           'delivery_earning', $5, NOW()+INTERVAL '7 days'
         ),
         (
           $1, 'nearkart', NULL,
           'delivery_share', $6, NOW()
         )`,
        [
          orderId,
          order.shop_id,
          money(subtotal - shopCommission),
          shopCommission,
          DELIVERY_EARNING,
          NEARKART_DELIVERY_SHARE,
        ]
      );

      await client.query(
        `UPDATE orders
         SET payment_status='paid',
             status='pending'
         WHERE id=$1`,
        [orderId]
      );

      await client.query("COMMIT");
      transactionStarted = false;

      const shopQ = await pool.query(
        `SELECT owner_id
         FROM shops
         WHERE id=$1`,
        [order.shop_id]
      );

      if (shopQ.rowCount) {
        await sendPushToUser(
          shopQ.rows[0].owner_id,
          "New NearKart order",
          `Paid order #${String(orderId).slice(0, 8)} received`,
          { orderId, status: "pending" },
          "new_order"
        );
      }

      await sendPushToUser(
        req.user.id,
        "Payment successful",
        "Your NearKart payment was verified and your order is placed.",
        { orderId, status: "pending" },
        "payment_success"
      );

      return res.json({
        verified: true,
        orderId,
        paymentStatus: "paid",
        message: "Payment verified and order placed.",
      });
    } catch (e) {
      if (transactionStarted) {
        await client.query("ROLLBACK");
      }

      console.error("Razorpay verification error:", e.message);

      return res.status(400).json({
        error: e.message || "Payment verification failed.",
      });
    } finally {
      client.release();
    }
  }
);

 // ============================================================
 // GET CUSTOMER ORDERS
 // ============================================================

app.get(
  "/api/orders",
  auth,
  roles("customer"),
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT
           o.id,
           o.shop_id,
           s.shop_name,
           o.status,
           o.subtotal,
           o.delivery_fee,
           o.total,
           o.payment_status,
           o.address,
           o.created_at,
           o.cancel_until,
           COALESCE(
             (
               SELECT json_agg(
                 json_build_object(
                   'productId', oi.product_id,
                   'name', p.name,
                   'quantity', oi.quantity,
                   'unitPrice', oi.unit_price,
                   'images', p.images
                 )
               )
               FROM order_items oi
               LEFT JOIN products p
                 ON p.id = oi.product_id
               WHERE oi.order_id = o.id
             ),
             '[]'::json
           ) AS items
         FROM orders o
         LEFT JOIN shops s
           ON s.id = o.shop_id
         WHERE o.customer_id = $1
         ORDER BY o.created_at DESC
         LIMIT 100`,
        [req.user.id]
      );

      return res.json(q.rows);
    } catch (e) {
      console.error("Get customer orders error:", e.message);

      return res.status(500).json({
        error: "Could not load orders."
      });
    }
  }
);

           
// ============================================================
// CANCEL ORDER
// ============================================================

app.post(
  "/api/orders/:id/cancel",
  auth,
  roles("customer"),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const q =
        await client.query(
          `SELECT *
           FROM orders
           WHERE id=$1
           AND customer_id=$2
           FOR UPDATE`,
          [
            req.params.id,
            req.user.id,
          ]
        );

      if (!q.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const o = q.rows[0];

      if (
        new Date() >
        new Date(
          o.cancel_until
        )
      ) {
        return res.status(400).json({
          error:
            "30-second cancellation window has ended",
        });
      }

      if (
        o.cancellation_status ===
        "cancelled"
      ) {
        return res.status(400).json({
          error:
            "Already cancelled",
        });
      }

      await client.query(
        `UPDATE orders
         SET
           status='cancelled',
           cancellation_status='cancelled',
           payment_status='refund_pending'
         WHERE id=$1`,
        [o.id]
      );

      await client.query(
        `UPDATE financial_ledger
         SET status='reversed'
         WHERE order_id=$1
         AND status='pending'`,
        [o.id]
      );

      await client.query(
        "COMMIT"
      );

      const shopQ =
        await pool.query(
          `SELECT s.owner_id
           FROM shops s
           JOIN orders o
             ON o.shop_id=s.id
           WHERE o.id=$1`,
          [o.id]
        );

      if (shopQ.rowCount) {
        await sendPushToUser(
          shopQ.rows[0]
            .owner_id,
          "Order cancelled",
          "Customer cancelled the order within 30 seconds",
          {
            orderId: o.id,
            status:
              "cancelled",
          },
          "order_cancelled"
        );
      }

      await sendPushToUser(
        req.user.id,
        "Order cancelled",
        "Refund has been queued for this eligible cancellation",
        {
          orderId: o.id,
          status:
            "refund_pending",
        },
        "refund_pending"
      );

      res.json({
        message:
          "Order cancelled; Cashfree refund must be initiated by the payment service",
        refundStatus:
          "pending",
      });
    } catch (e) {
      await client.query(
        "ROLLBACK"
      );

      res.status(500).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// ORDER STATUS
// ============================================================

app.post(
  "/api/orders/:id/status",
  auth,
  roles(
    "shopkeeper",
    "delivery",
    "admin"
  ),
  async (req, res) => {
    const allowed = [
      "accepted",
      "preparing",
      "ready",
      "assigned",
      "picked_up",
      "out_for_delivery",
      "delivered",
    ];

    const {
      status,
    } = req.body;

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error:
          "Invalid status",
      });
    }

    const extra =
      status === "delivered"
        ? ", delivered_at=NOW()"
        : "";

    const q =
      await pool.query(
        `UPDATE orders
         SET status=$1${extra}
         WHERE id=$2
         RETURNING *`,
        [
          status,
          req.params.id,
        ]
      );

    if (!q.rowCount) {
      return res.status(404).json({
        error:
          "Order not found",
      });
    }

    const o = q.rows[0];

    const labels = {
      accepted:
        "Order accepted",
      preparing:
        "Order is being prepared",
      ready:
        "Order is ready",
      assigned:
        "Delivery partner assigned",
      picked_up:
        "Order picked up",
      out_for_delivery:
        "Order is out for delivery",
      delivered:
        "Order delivered",
    };

    await sendPushToUser(
      o.customer_id,
      "NearKart",
      labels[status] ||
        "Order updated",
      {
        orderId: o.id,
        status,
      },
      "order_status"
    );

    if (
      o.delivery_partner_id
    ) {
      await sendPushToUser(
        o.delivery_partner_id,
        "NearKart",
        labels[status] ||
          "Order updated",
        {
          orderId: o.id,
          status,
        },
        "order_status"
      );
    }

    res.json(o);
  }
);

// ============================================================
// ASSIGN DELIVERY PARTNER
// ============================================================

app.post(
  "/api/orders/:id/assign",
  auth,
  roles("admin"),
  async (req, res) => {
    const {
      deliveryPartnerId,
    } = req.body;

    const q =
      await pool.query(
        `UPDATE orders
         SET
           delivery_partner_id=$1,
           status='assigned'
         WHERE id=$2
         RETURNING *`,
        [
          deliveryPartnerId,
          req.params.id,
        ]
      );

    if (!q.rowCount) {
      return res.status(404).json({
        error:
          "Order not found",
      });
    }

    const o = q.rows[0];

    await sendPushToUser(
      o.customer_id,
      "NearKart",
      "Delivery partner assigned to your order",
      {
        orderId: o.id,
        status: "assigned",
      },
      "delivery_assigned"
    );

    await sendPushToUser(
      o.delivery_partner_id,
      "NearKart",
      "New delivery assigned",
      {
        orderId: o.id,
        status: "assigned",
      },
      "delivery_assigned"
    );

    res.json(o);
  }
);

// ============================================================
// DELIVERY LOCATION
// ============================================================

app.post(
  "/api/delivery/location",
  auth,
  roles("delivery"),
  async (req, res) => {
    const {
      orderId,
      latitude,
      longitude,
      accuracy,
    } = req.body;

    const own =
      await pool.query(
        `SELECT id
         FROM orders
         WHERE id=$1
         AND delivery_partner_id=$2
         AND status IN(
           'assigned',
           'picked_up',
           'out_for_delivery'
         )`,
        [
          orderId,
          req.user.id,
        ]
      );

    if (!own.rowCount) {
      return res.status(403).json({
        error:
          "Order not assigned",
      });
    }

    await pool.query(
      `INSERT INTO delivery_locations
       (
         order_id,
         delivery_partner_id,
         latitude,
         longitude,
         accuracy
       )
       VALUES($1,$2,$3,$4,$5)`,
      [
        orderId,
        req.user.id,
        latitude,
        longitude,
        accuracy || null,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

// ============================================================
// LIVE LOCATION
// ============================================================

app.get(
  "/api/orders/:id/live-location",
  auth,
  async (req, res) => {
    const q =
      await pool.query(
        `SELECT
           latitude,
           longitude,
           accuracy,
           recorded_at
         FROM delivery_locations
         WHERE order_id=$1
         ORDER BY recorded_at DESC
         LIMIT 1`,
        [req.params.id]
      );

    if (!q.rowCount) {
      return res.status(404).json({
        error:
          "No live location yet",
      });
    }

    res.json(
      q.rows[0]
    );
  }
);

// ============================================================
// ADMIN ORDER EVENT
// ============================================================

app.post(
  "/api/admin/notifications/order-event",
  auth,
  roles("admin"),
  async (req, res) => {
    try {
      const {
        orderId,
        event,
      } = req.body;

      const q =
        await pool.query(
          `SELECT
             customer_id,
             delivery_partner_id
           FROM orders
           WHERE id=$1`,
          [orderId]
        );

      if (!q.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const o = q.rows[0];

      const map = {
        payment_success: [
          "Payment successful",
          "Your NearKart payment was successful",
          "payment_success",
        ],

        refund_initiated: [
          "Refund initiated",
          "Your eligible refund has been initiated",
          "refund_initiated",
        ],

        refund_success: [
          "Refund completed",
          "Your refund has been completed by the payment provider",
          "refund_success",
        ],

        complaint_update: [
          "Complaint updated",
          "There is an update on your support complaint",
          "complaint_update",
        ],
      };

      if (!map[event]) {
        return res.status(400).json({
          error:
            "Unsupported event",
        });
      }

      const [
        title,
        body,
        type,
      ] = map[event];

      await sendPushToUser(
        o.customer_id,
        title,
        body,
        {
          orderId,
          type,
        },
        type
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ROUTE / DISTANCE / ETA
// ============================================================

app.get(
  "/api/orders/:id/route",
  auth,
  async (req, res) => {
    try {
      const q =
        await pool.query(
          `
          SELECT
            o.id,
            o.customer_id,
            o.delivery_partner_id,
            o.address,

            dl.latitude AS driver_latitude,
            dl.longitude AS driver_longitude

          FROM orders o

          LEFT JOIN LATERAL (
            SELECT
              latitude,
              longitude
            FROM delivery_locations
            WHERE order_id=o.id
            ORDER BY recorded_at DESC
            LIMIT 1
          ) dl ON TRUE

          WHERE o.id=$1
          `,
          [req.params.id]
        );

      if (!q.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const o = q.rows[0];

      const allowed =
        req.user.role === "admin" ||
        req.user.id ===
          o.customer_id ||
        req.user.id ===
          o.delivery_partner_id;

      if (!allowed) {
        return res.status(403).json({
          error:
            "Forbidden",
        });
      }

      if (
        o.driver_latitude ==
          null ||
        o.driver_longitude ==
          null
      ) {
        return res.status(404).json({
          error:
            "Driver GPS not available yet",
        });
      }

      const a =
        o.address || {};

      const destinationLat =
        Number(
          a.latitude ??
            a.lat
        );

      const destinationLng =
        Number(
          a.longitude ??
            a.lng ??
            a.lon
        );

      if (
        !Number.isFinite(
          destinationLat
        ) ||
        !Number.isFinite(
          destinationLng
        )
      ) {
        return res.status(400).json({
          error:
            "Order address is missing latitude/longitude",
        });
      }

      const coords =
        `${Number(
          o.driver_longitude
        )},${Number(
          o.driver_latitude
        )};${destinationLng},${destinationLat}`;

      const url =
        `https://router.project-osrm.org/route/v1/driving/` +
        `${encodeURIComponent(
          coords
        )}?overview=full&geometries=geojson&steps=false`;

      const r =
        await fetch(url, {
          headers: {
            "User-Agent":
              "NearKart/5.0 route service",
          },
        });

      if (!r.ok) {
        return res.status(502).json({
          error:
            "Routing service unavailable",
        });
      }

      const data =
        await r.json();

      if (
        data.code !== "Ok" ||
        !data.routes?.length
      ) {
        return res.status(400).json({
          error:
            data.message ||
            "No route found",
        });
      }

      const route =
        data.routes[0];

      res.json({
        distanceMeters:
          route.distance,

        distanceKm:
          Number(
            (
              route.distance /
              1000
            ).toFixed(2)
          ),

        durationSeconds:
          route.duration,

        etaMinutes:
          Math.max(
            1,
            Math.ceil(
              route.duration /
                60
            )
          ),

        driver: {
          latitude:
            Number(
              o.driver_latitude
            ),
          longitude:
            Number(
              o.driver_longitude
            ),
        },

        destination: {
          latitude:
            destinationLat,
          longitude:
            destinationLng,
        },

        geometry:
          route.geometry,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ADMIN FINANCIALS
// ============================================================

app.get(
  "/api/admin/financials",
  auth,
  roles("admin"),
  async (req, res) => {
    const q =
      await pool.query(
        `
        SELECT
          owner_type,
          entry_type,
          status,
          SUM(amount)::numeric(14,2)
            AS amount

        FROM financial_ledger

        GROUP BY
          owner_type,
          entry_type,
          status

        ORDER BY
          owner_type,
          entry_type,
          status
        `
      );

    res.json(q.rows);
  }
);

// ============================================================
// ADMIN SHOP DECISION
// ============================================================

app.post(
  "/api/admin/shops/:id/decision",
  auth,
  roles("admin"),
  async (req, res) => {
    const {
      status,
    } = req.body;

    if (
      ![
        "approved",
        "rejected",
        "suspended",
      ].includes(status)
    ) {
      return res.status(400).json({
        error:
          "Invalid decision",
      });
    }

    const q =
      await pool.query(
        `UPDATE shops
         SET status=$1
         WHERE id=$2
         RETURNING *`,
        [
          status,
          req.params.id,
        ]
      );

    res.json(
      q.rows[0] || null
    );
  }
);

// ============================================================
// ADMIN SETTLEMENT RELEASE
// ============================================================

app.post(
  "/api/admin/settlements/release",
  auth,
  roles("admin"),
  async (req, res) => {
    const q =
      await pool.query(
        `
        UPDATE financial_ledger

        SET status='available'

        WHERE
          status='pending'
          AND available_at<=NOW()

        RETURNING
          id,
          owner_type,
          owner_id,
          amount,
          order_id
        `
      );

    res.json({
      released: q.rows,
    });
  }
);

// ============================================================
// CUSTOMER ADDRESSES
// ============================================================

// Get all saved addresses for the logged-in customer
app.get(
  "/api/addresses",
  auth,
  roles("customer"),
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT *
         FROM addresses
         WHERE user_id=$1
         ORDER BY is_default DESC, created_at DESC`,
        [req.user.id]
      );

      res.json(q.rows);
    } catch (e) {
      console.error("Get addresses error:", e.message);
      res.status(500).json({ error: e.message });
    }
  }
);

// Save a new address
app.post(
  "/api/addresses",
  auth,
  roles("customer"),
  async (req, res) => {
    const client = await pool.connect();

    try {
      const {
        fullName,
        phone,
        houseAddress,
        city,
        state,
        pincode,
        latitude,
        longitude,
        label = "Home",
        isDefault = false,
      } = req.body;

      if (
        !fullName ||
        !phone ||
        !houseAddress ||
        !city ||
        !state ||
        !pincode
      ) {
        return res.status(400).json({
          error:
            "Full name, phone, address, city, state and pincode are required",
        });
      }

      await client.query("BEGIN");

      // Only one default address per customer
      if (isDefault) {
        await client.query(
          `UPDATE addresses
           SET is_default=FALSE,
               updated_at=NOW()
           WHERE user_id=$1`,
          [req.user.id]
        );
      }

      const q = await client.query(
        `INSERT INTO addresses
         (
           user_id,
           full_name,
           phone,
           house_address,
           city,
           state,
           pincode,
           latitude,
           longitude,
           label,
           is_default
         )
         VALUES
         (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
         )
         RETURNING *`,
        [
          req.user.id,
          String(fullName).trim(),
          String(phone).trim(),
          String(houseAddress).trim(),
          String(city).trim(),
          String(state).trim(),
          String(pincode).trim(),
          latitude == null ? null : Number(latitude),
          longitude == null ? null : Number(longitude),
          String(label || "Home").trim(),
          Boolean(isDefault),
        ]
      );

      await client.query("COMMIT");

      res.status(201).json(q.rows[0]);
    } catch (e) {
      await client.query("ROLLBACK");

      console.error("Save address error:", e.message);

      res.status(500).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// Delete one address belonging to the logged-in customer
app.delete(
  "/api/addresses/:id",
  auth,
  roles("customer"),
  async (req, res) => {
    try {
      const q = await pool.query(
        `DELETE FROM addresses
         WHERE id=$1
         AND user_id=$2
         RETURNING *`,
        [req.params.id, req.user.id]
      );

      if (!q.rowCount) {
        return res.status(404).json({
          error: "Address not found",
        });
      }

      res.json({
        message: "Address deleted",
        address: q.rows[0],
      });
    } catch (e) {
      console.error("Delete address error:", e.message);

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// Make an address the customer's default address
app.post(
  "/api/addresses/:id/default",
  auth,
  roles("customer"),
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const check = await client.query(
        `SELECT id
         FROM addresses
         WHERE id=$1
         AND user_id=$2`,
        [req.params.id, req.user.id]
      );

      if (!check.rowCount) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Address not found",
        });
      }

      // Remove old default address
      await client.query(
        `UPDATE addresses
         SET is_default=FALSE,
             updated_at=NOW()
         WHERE user_id=$1`,
        [req.user.id]
      );

      // Set selected address as default
      const q = await client.query(
        `UPDATE addresses
         SET is_default=TRUE,
             updated_at=NOW()
         WHERE id=$1
         AND user_id=$2
         RETURNING *`,
        [req.params.id, req.user.id]
      );

      await client.query("COMMIT");

      res.json(q.rows[0]);
    } catch (e) {
      await client.query("ROLLBACK");

      console.error("Default address error:", e.message);

      res.status(500).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// START SERVER
// ============================================================



app.listen(
  PORT,
  () =>
    console.log(
      `NearKart backend v2 running on ${PORT}`
    )
);