import tokenHelper from "./token-helper.js";
class CookieHelper {
  setAccessToken(req, res, next) {
    const { id, login } = req.body;
    const access_token = tokenHelper.createAccessToken({
      id: id,
      login: login,
    });
    res.cookie("access", access_token, { httpOnly: true });
    next();
  }
  setRefreshToken(req, res, next) {
    const { id, uuid } = req.body;
    const refresh_token = tokenHelper.createRefreshToken({
      id: id,
      uuid: uuid,
    });
    res.cookie("refresh", refresh_token, { httpOnly: true });
    next();
  }
}
export default new CookieHelper();
