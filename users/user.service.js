const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./../_helpers/db');
const User = db.User;
const Logs = db.Logs;

module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    getLogs: getAuditLogs,
    logOut
};

async function authenticate({ username, password }, client_ip) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        const { hash, ...userWithoutHash } = user.toObject();
        const log = await Logs.create({ login_time: new Date(), client_ip, user_id: user._id });
        await User.findOneAndUpdate({ _id: user._id }, { $push: { logs: log._id } })
        const token = jwt.sign({ sub: user.id, login_id: log._id, role: user.role }, config.secret);
        userWithoutHash['login_id'] = log._id;
        return {
            ...userWithoutHash,
            token,
        };
    }
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}

async function getAuditLogs({ id, role }) {
    //get all users except current user

    if (role === 'USER' || !role) return;

    return await User.find({ _id: { $ne: id } }, { hash: 0 }).populate('logs');

}

async function logOut(log_id) {

    return await Logs.findOneAndUpdate({ _id: log_id }, { $set: { logout_time: new Date() } })

}