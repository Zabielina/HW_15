import { dbconfig } from "../dbconfig.js";
import { v4 as uuidv4 } from "uuid";
class Token {
  async add_token(req, res, next) {
    const uuid = uuidv4();
    const new_row = await dbconfig.query(
      "INSERT INTO tokens (id, uuid) VALUES($1,$2) RETURNING *",
      [req.body.id, uuid]
    );
    req.body.uuid = new_row.rows[0].uuid;
    next();
  }
  async delete_token(id) {
    console.log(id);
    await dbconfig.query("DELETE FROM tokens WHERE id=$1", [id]);
  }

  async get_one_token(data) {
    const { id, uuid } = data;
    const row = await dbconfig.query(
      "SELECT * FROM tokens WHERE id=$1 AND uuid=$2",
      [id, uuid]
    );
    if (row.rowCount == 1) {
      return true;
    }
    return false;
  }
}

export default new Token();
