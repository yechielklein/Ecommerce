const fs = require('fs');
const crypto = require('crypto');
const util = require('util');

const Repository = require('./repository');


const scrypt = util.promisify(crypto.scrypt);

class usersRepository extends Repository {
	async create(attributes) {
		attributes.id = this.randomId();

		const salt = crypto.randomBytes(8).toString('hex');
		const buff = await scrypt(attributes.password, salt, 64);

		const records = await this.getAll();
		const record = {
			...attributes,
			password: `${buff.toString('hex')}.${salt}`
		};

		records.push(record);

		await this.writeAll(records);

		return record;
	};

	async comparePasswords(saved, supplied) {
		const [hashed, salt] = saved.split('.');
		const hashSuppliedBuff = await scrypt(supplied, salt, 64);

		return hashed === hashSuppliedBuff.toString('hex');
	};
};

module.exports = new usersRepository('users.json');