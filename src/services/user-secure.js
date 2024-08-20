
import jwt from "jsonwebtoken";

import Token from "../postgres/models/Token.js";
import User from "../postgres/models/User.js";

class Secure {
  generateAccessToken(payload) {
    return jwt.sign(payload, process.env.ACCESS_KEY_JWT, {
      expiresIn: process.env.TIME_ACCESS_TOKEN,
    });
  }

  generateRefreshToken(payload) {
    return jwt.sign(payload, process.env.REFRESH_KEY_JWT, {
      expiresIn: process.env.TIME_REFRESH_TOKEN,
    });
  }

  authenticateAccessToken(req, res, next) {
    const token = req.cookies.access;
    if (!token) {
      return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_KEY_JWT, (err, payload) => {
      if (err) {
        if (err instanceof jwt.TokenExpiredError) {
       
          const refreshToken = req.cookies.refresh;
          if (refreshToken) {
            jwt.verify(refreshToken, process.env.REFRESH_KEY_JWT, async (err, refreshPayload) => {
              if (err) {
                return res.sendStatus(403);
              }
           
              const newAccessToken = this.generateAccessToken({ id: refreshPayload.id, login: refreshPayload.login });
              res.cookie("access", newAccessToken, { httpOnly: true });
              res.locals.user = refreshPayload.login;
              return next();
            });
          } else {
            return res.sendStatus(403);
          }
        } else {
          return res.sendStatus(403);
        }
      } else {
        res.locals.user = payload.login;
        next();
      }
    });
  }

  async check_token(req, res, next) {
    const accessToken = req.cookies.access;
    if (accessToken) {
      jwt.verify(accessToken, process.env.ACCESS_KEY_JWT, async (err, payload) => {
        if (err && err.name === "TokenExpiredError") {
          const refreshToken = req.cookies.refresh;
          if (refreshToken) {
            jwt.verify(refreshToken, process.env.REFRESH_KEY_JWT, async (err, refreshPayload) => {
              if (!err && await Token.get_one_token(refreshPayload.id)) {
                const login = (await User.get_user_by_id(refreshPayload.id)).login;
                const newAccessToken = this.generateAccessToken({ id: refreshPayload.id, login });
                res.cookie("access", newAccessToken, { httpOnly: true });
                res.locals.user = login;
              }
            });
          }
        } else if (payload) {
          res.locals.user = payload.login;
        }
        next();
      });
    } else {
      next();
    }
  }

  async get_payload_from_access_token(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, process.env.ACCESS_KEY_JWT, (err, payload) => {
        if (err) {
          resolve(null);
        } else {
          Token.delete_token(payload.id);
          resolve(payload);
        }
      });
    });
  }

  get_payload_from_refresh_token(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, process.env.REFRESH_KEY_JWT, (err, payload) => {
        if (err) {
          resolve(null);
        } else {
          resolve(payload);
        }
      });
    });
  }
}

export default new Secure();
