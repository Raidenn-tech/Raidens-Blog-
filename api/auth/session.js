
const crypto = require("crypto");

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      loggedIn: false,
      message: "Method not allowed"
    });
  }

  try {
    const cookies = req.headers.cookie || "";
    const match = cookies.match(
      /(?:^|;\s*)raidens_session=([^;]+)/
    );

    if (!match) {
      return res.status(200).json({
        loggedIn: false,
        subscribed: false
      });
    }

    const secret = process.env.SESSION_SECRET;

    if (!secret) {
      return res.status(500).json({
        loggedIn: false,
        message: "Server configuration error"
      });
    }

    const parts = match[1].split(".");

    if (parts.length !== 2) {
      throw new Error("Invalid session");
    }

    const [payload, signature] = parts;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      throw new Error("Invalid signature");
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      data.subscribed !== true ||
      typeof data.expires !== "number" ||
      data.expires <= Date.now()
    ) {
      throw new Error("Session expired");
    }

    return res.status(200).json({
      loggedIn: true,
      subscribed: true
    });

  } catch (error) {
    res.setHeader(
      "Set-Cookie",
      "raidens_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    );

    return res.status(200).json({
      loggedIn: false,
      subscribed: false
    });
  }
};
