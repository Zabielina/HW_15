
import { Router } from "express";
import secure from "../services/user-secure.js";
import userController from "../controllers/user-controller.js";
import Token from "../postgres/models/Token.js";

const user_router = Router();


user_router.get("/signup", (req, res) => {
  res.render("form_register", { title: "Registration Form" });
});

user_router.post(
  "/signup",
  userController.add_user, 
  async (req, res) => {
    const userId = req.body.id;
    const userLogin = req.body.login;

    
    const accessToken = secure.generateAccessToken({ id: userId, login: userLogin });
    const refreshToken = secure.generateRefreshToken({ id: userId, login: userLogin });


    res.cookie("access", accessToken, { httpOnly: true });
    res.cookie("refresh", refreshToken, { httpOnly: true });

    res.json({ accessToken, refreshToken });
  }
);

user_router.get("/signin", (req, res) => {
  res.render("form_auth", { title: "Auth Form" });
});

user_router.post(
  "/signin",
  userController.check_user,
  async (req, res) => {
    const userId = req.body.id;
    const userLogin = req.body.login;

   
    const accessToken = secure.generateAccessToken({ id: userId, login: userLogin });
    const refreshToken = secure.generateRefreshToken({ id: userId, login: userLogin });


    res.cookie("access", accessToken, { httpOnly: true });
    res.cookie("refresh", refreshToken, { httpOnly: true });

    res.redirect("/");
  }
);


user_router.get("/logout", async (req, res) => {
  const accessToken = req.cookies.access;

  
  if (accessToken) {
    const payload = await secure.get_payload_from_access_token(accessToken);
    if (payload) {
      await Token.delete_token(payload.id); 
    }
  }

  res.clearCookie("refresh");
  res.clearCookie("access");
  req.session.destroy();
  res.redirect("/");
});


user_router.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, process.env.REFRESH_KEY_JWT, async (err, payload) => {
    if (err) return res.sendStatus(403);

    const tokenExists = await Token.get_one_token(payload.id);
    if (!tokenExists) return res.sendStatus(403);

    const newAccessToken = secure.generateAccessToken({ id: payload.id, login: payload.login });
    res.cookie("access", newAccessToken, { httpOnly: true });
    res.json({ accessToken: newAccessToken });
  });
});

user_router.get("/", secure.authenticateAccessToken, (req, res) => {
  res.json({ user: res.locals.user });
});

export default user_router;
