import userSecure from "../services/user-secure.js";
class TokenHelper {
  createAccessToken(data) {
    const { id, login } = data;
    const payload = {
      type: "access",
      id: id,
      login: login,
    };
    return userSecure.generateAccessToken(payload);
  }
  createRefreshToken(data) {
    const { id, uuid } = data;
    const payload = {
      type: "refresh",
      id: id,
      uuid: uuid,
    };
    return userSecure.generateRefreshToken(payload);
  }
}
export default new TokenHelper();
