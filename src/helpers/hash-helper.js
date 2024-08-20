import bcrypt from "bcrypt";
class HashHelper {
  //створення хеша
  async get_hash(password) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  }
  //порівняння паролів
  async compare_hash(password, hash) {
    return await bcrypt.compare(password, hash);
  }
}
export default new HashHelper();
