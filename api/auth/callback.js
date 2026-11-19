const crypto = require("crypto");

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  try {
    const { code, state, error } = req.query;
    const cookies = req.headers.cookie || "";
    const match = cookies.match(/(?:^|;\s*)oauth_state=([^;]+)/);
    const savedState = match ? match[1] : "";

    if (error || !code || !state || !savedState || state !== savedState) {
      return res.status(400).send("Login tidak valid.");
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const sessionSecret = process.env.SESSION_SECRET;

    if (!clientId || !clientSecret || !sessionSecret) {
      return res.status(500).send("Konfigurasi server belum lengkap.");
    }

    const redirectUri =
      "https://raidens-blog.vercel.app/api/auth/callback";

    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: "authorization_code"
        })
      }
    );

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.access_token) {
      return res.status(400).send("Login Google gagal.");
    }

    const channelResponse = await fetch(
      "https://www.googleapis.com/youtube/v3/channels?part=id&forHandle=dkaahmdy",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`
        }
      }
    );

    const channelData = await channelResponse.json();
    const channelId = channelData.items?.[0]?.id;

    if (!channelResponse.ok || !channelId) {
      return res.status(500).send("Channel tidak ditemukan.");
    }

    const subResponse = await fetch(
      "https://www.googleapis.com/youtube/v3/subscriptions?part=snippet&mine=true&forChannelId=" +
      encodeURIComponent(channelId),
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`
        }
      }
    );

    const subData = await subResponse.json();

    if (!subResponse.ok) {
      return res.status(400).send("Pemeriksaan subscribe gagal.");
    }

    const subscribed = (subData.items || []).some(
      item => item.snippet.resourceId.channelId === channelId
    );

    res.setHeader("Set-Cookie", [
      "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0"
    ]);

    if (!subscribed) {
      return res.redirect("/?subscription=not_found");
    }

    const payload = Buffer.from(JSON.stringify({
      subscribed: true,
      expires: Date.now() + 3600000
    })).toString("base64url");

    const signature = crypto
      .createHmac("sha256", sessionSecret)
      .update(payload)
      .digest("base64url");

    const session = `${payload}.${signature}`;

    res.setHeader("Set-Cookie", [
      "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0",
      `raidens_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600`
    ]);

    return res.redirect("/?subscription=verified");

  } catch (err) {
    return res.status(500).send("Terjadi kesalahan server.");
  }
};
  
