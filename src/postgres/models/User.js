import { dbconfig } from "../dbconfig.js";
class User {
  async add_user(data) {
    const { login, email, password } = data;
    const user = await dbconfig.query(
      "INSERT INTO users(login, email, password) VALUES($1,$2,$3) RETURNING *",
      [data.login, data.email, data.password]
    );
    return user.rows[0].id;
  }

  async get_user_by_id(id) {
    const user = await dbconfig.query("SELECT * FROM users WHERE id=$1", [id]);
    return user.rows[0];
  }

  async get_user_by_login(login) {
    const user = await dbconfig.query("SELECT * FROM users WHERE login=$1", [
      login,
    ]);
    return user.rows[0];
  }
}

export default new User();
