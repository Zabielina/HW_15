import User from "../postgres/models/User.js";
import hashHelper from "../helpers/hash-helper.js";
class UserController {
  async add_user(req, res, next) {
    const { login, email, password } = req.body;
    const hash = await hashHelper.get_hash(password);
    req.body.password = hash;
    req.body.id = await User.add_user(req.body);
    next();
  }

  async check_user(req, res, next) {
    const { login, password } = req.body;
    const user = await User.get_user_by_login(login);
    req.body.id = user.id;
    const is_success = await hashHelper.compare_hash(password, user.password);
    if (is_success === true) {
      next();
    }
  }
}
export default new UserController();
